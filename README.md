# extensions

此项目主要是实现一个通过istio-ingressgateway来拦截网关的请求， 使我们可以自定义服务的流量来实现网关的权限管理。实现原理主要是使用wasm 来扩展envoy的能力。

架构图如下:

![extensions](image/wasm-ingressgateway.png)

这样做对业务没有依赖, 所有的业务服务不需要关注权限的业务。所有的权限有user(用户校验服务)来验证用户是否符合权限的要求