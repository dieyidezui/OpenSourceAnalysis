>OkHttp在一个月前迎来了3.4.x时代，内部对架构做了大量的修改，移除了HttpEngine的概念，通过Interceptor与Chain用职责链模式来完成整个请求的过程，内部透明的进行了重试，重定向，header替换，gzip解压，存取cookie，读写缓存等过程。

笔者研读了源码后觉得十分精彩，于是想分享一下OkHttp的网络请求执行流程与架构。因而不会过多关注其API，但是OkHttp提供了很多实用简洁的API来帮助用户完成网络请求，具体的用法可以关注[官方wiki](https://github.com/square/okhttp/wiki)

##OkHttp简介
OkHttp是一个精巧的网络请求库，有如下特性:

-  支持http2，对一台机器的所有请求共享同一个socket
-  内置连接池，支持连接复用，减少延迟
-  支持透明的gzip压缩响应体
-  通过缓存避免重复的请求
-  请求失败时自动重试主机的其他ip，自动重定向
-  好用的API

其本身就是一个很强大的库，再加上Retrofit2、Picasso的这一套组合拳，使其愈发的受到开发者的关注。

##流程解析
整个库整体的架构图是这样的:
![](http://7xpz14.com1.z0.glb.clouddn.com/okhttp_uml.png)

我们顺着一个请求的过程看一下，OkHttp是如何完成一个完整的网络请求的。

###初构请求
一个典型的请求过程是这样的，用一个构造好的OkHttpClient和Request获取到一个Call，然后执行call的异步或者同步方法取得Response或者处理异常，如下所示:

```java
OkHttpClient client = new OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .addInterceptor(...)
        ....
        .build();

Request request = new Request.Builder()
        .addHeader("Connection", "Keep-Alive")
        .url("http://www.dieyidezui.com")
        ....
        .build();
Call call = client.newCall(request);
call.enqueue(new Callback() {...});
```

这里实际上，Call的实现是一个RealCall的类，execute的代码如下:

```java
@Override public Response execute() throws IOException {
  synchronized (this) {
    if (executed) throw new IllegalStateException("Already Executed");
    executed = true;
  }
  try {
    client.dispatcher().executed(this);
    Response result = getResponseWithInterceptorChain();
    if (result == null) throw new IOException("Canceled");
    return result;
  } finally {
    client.dispatcher().finished(this);
  }
}
```

而enqueue实际上是RealCall的将内部类AsyncCall扔进了dispatcher中:`client.dispatcher().enqueue(new AsyncCall(responseCallback));`。AsyncCall实际上是一个Runnable，我们看一下进入线程池后真正执行的代码:

```java
@Override protected void execute() {
  boolean signalledCallback = false;
  try {
    Response response = getResponseWithInterceptorChain();
    if (retryAndFollowUpInterceptor.isCanceled()) {
      signalledCallback = true;
      responseCallback.onFailure(RealCall.this, new IOException("Canceled"));
    } else {
      signalledCallback = true;
      responseCallback.onResponse(RealCall.this, response);
    }
  } catch (IOException e) {
    if (signalledCallback) {
      // Do not signal the callback twice!
      Platform.get().log(INFO, "Callback failure for " + toLoggableString(), e);
    } else {
      responseCallback.onFailure(RealCall.this, e);
    }
  } finally {
    client.dispatcher().finished(this);
  }
}
```

于是这里需要介绍一个Dispatcher的概念。Dispatcher的本质是异步请求的管理器，控制最大请求并发数和单个主机的最大并发数，并持有一个线程池负责执行异步请求。对同步的请求只是用作统计。他是如何做到控制并发呢，其实原理就在上面的2个execute代码里面,真正网络请求执行前后会调用executed和finished方法，而对于AsyncCall的finished方法后，会根据当前并发数目选择是否执行队列中等待的AsyncCall。并且如果修改Dispatcher的maxRequests或者maxRequestsPerHost也会触发这个过程。

好的，在回到RealCall中，我们看到无论是execute还是enqueue，真正的Response是通过这个函数`getResponseWithInterceptorChain`获取的，其他的代码都是用作控制与回调。而这里就是真正请求的入口，也是到了OkHttp的一个很精彩的设计:Interceptor与Chain

###拦截器与调用链
上面分析到了，网络请求的入口实质上是在这里:

```java
private Response getResponseWithInterceptorChain() throws IOException {
  // Build a full stack of interceptors.
  List<Interceptor> interceptors = new ArrayList<>();
  interceptors.addAll(client.interceptors());
  interceptors.add(retryAndFollowUpInterceptor);
  interceptors.add(new BridgeInterceptor(client.cookieJar()));
  interceptors.add(new CacheInterceptor(client.internalCache()));
  interceptors.add(new ConnectInterceptor(client));
  if (!retryAndFollowUpInterceptor.isForWebSocket()) {
   interceptors.addAll(client.networkInterceptors());
  }
  interceptors.add(new CallServerInterceptor(
     retryAndFollowUpInterceptor.isForWebSocket()));
    
  Interceptor.Chain chain = new RealInterceptorChain(
     interceptors, null, null, null, 0, originalRequest);
  return chain.proceed(originalRequest);
}
```

这也是与旧版本不一致的地方，在3.4.x以前，没有这些内部的这些拦截器，只有用户的拦截器与网络拦截器。而Request和Response是通过HttpEngine来完成的。在RealCall实现了用户拦截器与RetryAndFollowUp的过程，而在HttpEngine内部处理了请求转换、Cookie、Cache、网络拦截器、连接网络的过程。值得一提的是，在旧版是获取到Response后调用网络拦截器的拦截。

而在这里，RealInterceptorChain会递归的创建并以此调用拦截器，去掉诸多异常，简化版代码如下:

```java
public Response proceed(Request request, StreamAllocation streamAllocation, HttpStream httpStream,
    Connection connection) throws IOException {
  if (index >= interceptors.size()) throw new AssertionError();
  
  // Call the next interceptor in the chain.
  RealInterceptorChain next = new RealInterceptorChain(
      interceptors, streamAllocation, httpStream, connection, index + 1, request);
  Interceptor interceptor = interceptors.get(index);
  
  Response response = interceptor.intercept(next);

  return response;
}
```

Chain与Interceptor会互相递归调用，直到链的尽头。

我们看到，通过职责链模式，清楚地切开了不同的逻辑，每个拦截器完成自己的职责，从而完成用户的网络请求。
大概流程是:

1. 先经过用户拦截器
2. RetryAndFollowUpInterceptor负责自动重试和进行必要的重定向
3. BridgeIntercetor负责将用户Request转换成一个实际的网络请求的Request，再调用下层的拦截器获取Response，最后再将网络Response转换成用户的Reponse
4. CacheInterceptor负责控制缓存
5. ConnectInterceptor负责进行连接主机
6. 网络拦截器进行拦截
7. CallServerInterceptor是真正和服务器通信，完成http请求

因为篇幅有限，笔者不会全部介绍，本文的重点会放在连接和通信的过程，其他的部分因为每个拦截器功能已经很明确了，代码也不长，有兴趣的朋友可以自己去看。

### 连接与通信
在RetryAndFollowUpInterceptor中,会创建StreamAllocation，然后交给下游的ConnectInterceptor，执行这样的代码:

```java
@Override public Response intercept(Chain chain) throws IOException {
  RealInterceptorChain realChain = (RealInterceptorChain) chain;
  Request request = realChain.request();
  StreamAllocation streamAllocation = realChain.streamAllocation();

  // We need the network to satisfy this request. Possibly for validating a conditional GET.
  boolean doExtensiveHealthChecks = !request.method().equals("GET");
  HttpStream httpStream = streamAllocation.newStream(client, doExtensiveHealthChecks);
  RealConnection connection = streamAllocation.connection();

  return realChain.proceed(request, streamAllocation, httpStream, connection);
}
```

这里会创建一个HttpStream，并且取到一个RealConnection，继续交给下游的CallServerInterceptor。
我们跟踪进去看看，StreamAllocation里面做了什么

```java
  public HttpStream newStream(OkHttpClient client, boolean doExtensiveHealthChecks) {
    int connectTimeout = client.connectTimeoutMillis();
    int readTimeout = client.readTimeoutMillis();
    int writeTimeout = client.writeTimeoutMillis();
    boolean connectionRetryEnabled = client.retryOnConnectionFailure();

    try {
      RealConnection resultConnection = findHealthyConnection(connectTimeout, readTimeout,
          writeTimeout, connectionRetryEnabled, doExtensiveHealthChecks);

      HttpStream resultStream;
      if (resultConnection.framedConnection != null) {
        resultStream = new Http2xStream(client, this, resultConnection.framedConnection);
      } else {
        resultConnection.socket().setSoTimeout(readTimeout);
        resultConnection.source.timeout().timeout(readTimeout, MILLISECONDS);
        resultConnection.sink.timeout().timeout(writeTimeout, MILLISECONDS);
        resultStream = new Http1xStream(
            client, this, resultConnection.source, resultConnection.sink);
      }

      synchronized (connectionPool) {
        stream = resultStream;
        return resultStream;
      }
    } catch (IOException e) {
      throw new RouteException(e);
    }
  }
```

这里的代码逻辑是这样的，找一个健康的连接，设置超时时间，然后根据协议创建一个HttpStream并返回。
继续跟进去看findHealthyConnection:

```java
private RealConnection findHealthyConnection(int connectTimeout, int readTimeout,
    int writeTimeout, boolean connectionRetryEnabled, boolean doExtensiveHealthChecks)
    throws IOException {
  while (true) {
    RealConnection candidate = findConnection(connectTimeout, readTimeout, writeTimeout,
        connectionRetryEnabled);

    // If this is a brand new connection, we can skip the extensive health checks.
    synchronized (connectionPool) {
      if (candidate.successCount == 0) {
        return candidate;
      }
    }

    // Do a (potentially slow) check to confirm that the pooled connection is still good. If it
    // isn't, take it out of the pool and start again.
    if (!candidate.isHealthy(doExtensiveHealthChecks)) {
      noNewStreams();
      continue;
    }

    return candidate;
  }
}
```

上面的逻辑也很简单，在findConnection中找一个连接，然后做健康检查，如果不健康就回收，并再次循环，那么真正寻找连接的代码就在findConnection里面了:

```java
private RealConnection findConnection(int connectTimeout, int readTimeout, int writeTimeout,
    boolean connectionRetryEnabled) throws IOException {
  Route selectedRoute;
  synchronized (connectionPool) {
    if (released) throw new IllegalStateException("released");
    if (stream != null) throw new IllegalStateException("stream != null");
    if (canceled) throw new IOException("Canceled");

    RealConnection allocatedConnection = this.connection;
    if (allocatedConnection != null && !allocatedConnection.noNewStreams) {
      return allocatedConnection;
    }

    // Attempt to get a connection from the pool.
    RealConnection pooledConnection = Internal.instance.get(connectionPool, address, this);
    if (pooledConnection != null) {
      this.connection = pooledConnection;
      return pooledConnection;
    }

    selectedRoute = route;
  }

  if (selectedRoute == null) {
    selectedRoute = routeSelector.next();
    synchronized (connectionPool) {
      route = selectedRoute;
      refusedStreamCount = 0;
    }
  }
  RealConnection newConnection = new RealConnection(selectedRoute);
  acquire(newConnection);

  synchronized (connectionPool) {
    Internal.instance.put(connectionPool, newConnection);
    this.connection = newConnection;
    if (canceled) throw new IOException("Canceled");
  }

  newConnection.connect(connectTimeout, readTimeout, writeTimeout, address.connectionSpecs(),
      connectionRetryEnabled);
  routeDatabase().connected(newConnection.route());

  return newConnection;
}
```

这里大概分成分成3大步:
1. 如果当前有连接并且符合要求的话，就直接返回
2. 如果线程池能取到一个符合要求的连接的话，就直接返回
3. 如果Route为空，从RouteSelector取一个Route，然后新建一个RealConnection，并放入ConnectionPool，随后调用connect，再返回

也就是说不管当前走的是步骤1还是2，一开始一定是从3开始的，也就是在RealConnection的connect中真正完成了socket连接。
connect里面代码比较长，真正要做的就是一件事，如果是https请求并且是http代理，则建立隧道连接，隧道连接请参考[RFC2817](http://www.ietf.org/rfc/rfc2817.txt)，否则建立普通连接。

这两者都调用了2个函数:`connectSocket(connectTimeout, readTimeout);
    establishProtocol(readTimeout, writeTimeout, connectionSpecSelector);`
但是隧道连接则多了一个代理认证的过程，可能会反复的connectSocket和构造请求。
    
进去看connectSocket:

```java
private void connectSocket(int connectTimeout, int readTimeout) throws IOException {
  Proxy proxy = route.proxy();
  Address address = route.address();

  rawSocket = proxy.type() == Proxy.Type.DIRECT || proxy.type() == Proxy.Type.HTTP
      ? address.socketFactory().createSocket()
      : new Socket(proxy);

  rawSocket.setSoTimeout(readTimeout);
  try {
    Platform.get().connectSocket(rawSocket, route.socketAddress(), connectTimeout);
  } catch (ConnectException e) {
    throw new ConnectException("Failed to connect to " + route.socketAddress());
  }
  source = Okio.buffer(Okio.source(rawSocket));
  sink = Okio.buffer(Okio.sink(rawSocket));
}
```

就是根据Route来创建socket，在connect，随后将rawSocket的InputStream与OutputStream包装成Source与Sink。这里提一下，OkHttp是依赖Okio的，Okio封装了Java的IO API，如这里的Source与Sink，非常简洁实用。

而establishProtocol里，如果是https则走TLS协议，生成一个SSLSocket，并进行握手和验证，同时如果是HTTP2或者SPDY3的话，则生成一个FrameConnection。这里不再多提，HTTP2和HTTP1.X大相径庭，我们这里主要是分析HTTP1.X的连接，后面有机会我们会单独开篇讲HTTP2。同时TLS相关的话题这里也一并略过，想了解的朋友可以看一看相应的Java API和HTTPS连接的资料。

再回到StreamAllcation.newStream的代码`resultStream = new Http1xStream(
            client, this, resultConnection.source, resultConnection.sink);`实质上HttpStream其实就是Request和Response读写Socket的抽象，我们看到Http1xStream取到了Socket输入输出流，随后在CallServerInterceptor可以拿来做读写。
            
我们看CallServerInterceptor做了什么:

```java
@Override public Response intercept(Chain chain) throws IOException {
  HttpStream httpStream = ((RealInterceptorChain) chain).httpStream();
  StreamAllocation streamAllocation = ((RealInterceptorChain) chain).streamAllocation();
  Request request = chain.request();

  long sentRequestMillis = System.currentTimeMillis();
  httpStream.writeRequestHeaders(request);

  if (HttpMethod.permitsRequestBody(request.method()) && request.body() != null) {
    Sink requestBodyOut = httpStream.createRequestBody(request, request.body().contentLength());
    BufferedSink bufferedRequestBody = Okio.buffer(requestBodyOut);
    request.body().writeTo(bufferedRequestBody);
    bufferedRequestBody.close();
  }

  httpStream.finishRequest();

  Response response = httpStream.readResponseHeaders()
      .request(request)
      .handshake(streamAllocation.connection().handshake())
      .sentRequestAtMillis(sentRequestMillis)
      .receivedResponseAtMillis(System.currentTimeMillis())
      .build();

  if (!forWebSocket || response.code() != 101) {
    response = response.newBuilder()
        .body(httpStream.openResponseBody(response))
        .build();
  }

  if ("close".equalsIgnoreCase(response.request().header("Connection"))
      || "close".equalsIgnoreCase(response.header("Connection"))) {
    streamAllocation.noNewStreams();
  }

  int code = response.code();
  if ((code == 204 || code == 205) && response.body().contentLength() > 0) {
    throw new ProtocolException(
        "HTTP " + code + " had non-zero Content-Length: " + response.body().contentLength());
  }

  return response;
}
```

CallServerInterceptor顾名思义，就是真正和Server进行通信的地方。这里也是按照HTTP协议，依次写入请求头，还有根据情况决定是否写入请求体。随后读响应头闭构造一个Response。

里面具体是如何实现呢，我们看Http1xStream：
首先是写头:

```java
String requestLine = RequestLine.get(
        request, streamAllocation.connection().route().proxy().type());
writeRequest(request.headers(), requestLine);
```

构造好请求行，进入writeRequest:

```java
public void writeRequest(Headers headers, String requestLine) throws IOException {
  if (state != STATE_IDLE) throw new IllegalStateException("state: " + state);
  sink.writeUtf8(requestLine).writeUtf8("\r\n");
  for (int i = 0, size = headers.size(); i < size; i++) {
    sink.writeUtf8(headers.name(i))
        .writeUtf8(": ")
        .writeUtf8(headers.value(i))
        .writeUtf8("\r\n");
  }
  sink.writeUtf8("\r\n");
  state = STATE_OPEN_REQUEST_BODY;
}
```

这里就一目了然了，就是一行行的写请求行和请求头到sink中

再看readResponse:

```java
public Response.Builder readResponse() throws IOException {
  if (state != STATE_OPEN_REQUEST_BODY && state != STATE_READ_RESPONSE_HEADERS) {
    throw new IllegalStateException("state: " + state);
  }

  try {
    while (true) {
      StatusLine statusLine = StatusLine.parse(source.readUtf8LineStrict());

      Response.Builder responseBuilder = new Response.Builder()
          .protocol(statusLine.protocol)
          .code(statusLine.code)
          .message(statusLine.message)
          .headers(readHeaders());

      if (statusLine.code != HTTP_CONTINUE) {
        state = STATE_OPEN_RESPONSE_BODY;
        return responseBuilder;
      }
    }
  } catch (EOFException e) {
    // Provide more context if the server ends the stream before sending a response.
    IOException exception = new IOException("unexpected end of stream on " + streamAllocation);
    exception.initCause(e);
    throw exception;
  }
}
```

也是一样的，从source中读请求行和请求头

最后看openResponseBody:

```java
@Override public ResponseBody openResponseBody(Response response) throws IOException {
  Source source = getTransferStream(response);
  return new RealResponseBody(response.headers(), Okio.buffer(source));
}

private Source getTransferStream(Response response) throws IOException {
  if (!HttpHeaders.hasBody(response)) {
    return newFixedLengthSource(0);
  }

  if ("chunked".equalsIgnoreCase(response.header("Transfer-Encoding"))) {
    return newChunkedSource(response.request().url());
  }

  long contentLength = HttpHeaders.contentLength(response);
  if (contentLength != -1) {
    return newFixedLengthSource(contentLength);
  }

  // Wrap the input stream from the connection (rather than just returning
  // "socketIn" directly here), so that we can control its use after the
  // reference escapes.
  return newUnknownLengthSource();
}
```

这里说一下就是根据请求的响应把包裹InputStream的source再次封装，里面做一些控制逻辑，然后再封装成ResponseBody。

例如FiexdLengthSource，就是期望获取到byte的长度是固定的值:

```java
private class FixedLengthSource extends AbstractSource {
  private long bytesRemaining;

  public FixedLengthSource(long length) throws IOException {
    bytesRemaining = length;
    if (bytesRemaining == 0) {
      endOfInput(true);
    }
  }

  @Override public long read(Buffer sink, long byteCount) throws IOException {
    if (byteCount < 0) throw new IllegalArgumentException("byteCount < 0: " + byteCount);
    if (closed) throw new IllegalStateException("closed");
    if (bytesRemaining == 0) return -1;

    long read = source.read(sink, Math.min(bytesRemaining, byteCount));
    if (read == -1) {
      endOfInput(false); // The server didn't supply the promised content length.
      throw new ProtocolException("unexpected end of stream");
    }

    bytesRemaining -= read;
    if (bytesRemaining == 0) {
      endOfInput(true);
    }
    return read;
  }

  @Override public void close() throws IOException {
    if (closed) return;

    if (bytesRemaining != 0 && !Util.discard(this, DISCARD_STREAM_TIMEOUT_MILLIS, MILLISECONDS)) {
      endOfInput(false);
    }

    closed = true;
  }
}
```

当读完期望的长度时就把这个RealConnection回收，如果少于期望的长度则抛异常。

OK,至此，整个请求的逻辑我们就都梳理了一遍。

###ConnectionPool
到了OkHttp3时代，ConnectionPool就是每个Client**独享**的了，我们刚才提到了ConnectionPool，那么他到底是如何运作呢。

ConnectionPool持有一个静态的线程池。

StreamAllocation不管通过什么方式，在获取到RealConnection后，RealConnection会添加一个对StreamAllocation的引用。
在每个RealConnection加入ConnectionPool后，如果当前没有在清理，就会把cleanUpRunnable加入线程池。

cleanUpRunnable里面是一个while(true),一个循环包括:
调用一次cleanUp方法进行清理并返回一个long, 如果是-1则退出，否则调用wait方法等待这个long值的时间

cleanUp代码如下:

```java
long cleanup(long now) {
  int inUseConnectionCount = 0;
  int idleConnectionCount = 0;
  RealConnection longestIdleConnection = null;
  long longestIdleDurationNs = Long.MIN_VALUE;

  // Find either a connection to evict, or the time that the next eviction is due.
  synchronized (this) {
    for (Iterator<RealConnection> i = connections.iterator(); i.hasNext(); ) {
      RealConnection connection = i.next();

      // If the connection is in use, keep searching.
      if (pruneAndGetAllocationCount(connection, now) > 0) {
        inUseConnectionCount++;
        continue;
      }

      idleConnectionCount++;

      // If the connection is ready to be evicted, we're done.
      long idleDurationNs = now - connection.idleAtNanos;
      if (idleDurationNs > longestIdleDurationNs) {
        longestIdleDurationNs = idleDurationNs;
        longestIdleConnection = connection;
      }
    }

    if (longestIdleDurationNs >= this.keepAliveDurationNs
        || idleConnectionCount > this.maxIdleConnections) {
      // We've found a connection to evict. Remove it from the list, then close it below (outside
      // of the synchronized block).
      connections.remove(longestIdleConnection);
    } else if (idleConnectionCount > 0) {
      // A connection will be ready to evict soon.
      return keepAliveDurationNs - longestIdleDurationNs;
    } else if (inUseConnectionCount > 0) {
      // All connections are in use. It'll be at least the keep alive duration 'til we run again.
      return keepAliveDurationNs;
    } else {
      // No connections, idle or in use.
      cleanupRunning = false;
      return -1;
    }
  }

  closeQuietly(longestIdleConnection.socket());

  // Cleanup again immediately.
  return 0;
}
```

他做了如下的工作:
遍历每一个RealConnection，通过引用数目确定哪些是空闲的，哪些是在使用中，同时找到空闲时间最长的RealConnection。
如果空闲数目超过最大空闲数或者空闲时间超过最大空闲时间，则清理掉这个RealConnection，并返回0，表示需要立刻再次清理
否则如果空闲的数目大于0个，则等待最大空闲时间-已有的最长空闲时间
否则如果使用中的数目大于0，则等待最大空闲时间
否则 返回 -1，并标识退出清除状态


同时如果某个RealConnection空闲后，会进入ConnectionPool.connectionBecameIdle方法,如果不可被复用，则被移除，否则立刻唤醒上面cleanUp的wait，再次清理，因为可能超过了最大空闲数目

这样通过一个静态的线程池，ConnectionPool做到了每个实例定期清理，保证不会超过最大空闲时间和最大空闲数目的策略。

##结语
OkHttp的源码剖析这里就告一段落了。作为开源的经典之作，OkHttp确实值得学习。笔者能力有限，如果写得不当之处还请大家指出改正。

这里是笔者的[个人博客地址](http://dieyidezui.com)

也欢迎关注笔者的微信公众号，会不定期的分享一些内容给大家
![](http://7xpz14.com1.z0.glb.clouddn.com/weixin_public.jpg)







