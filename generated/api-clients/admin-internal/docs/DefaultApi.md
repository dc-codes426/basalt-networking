# \DefaultApi

All URIs are relative to *http://localhost:3001*

Method | HTTP request | Description
------------- | ------------- | -------------
[**health**](DefaultApi.md#health) | **GET** /health | Dependency health check
[**ping**](DefaultApi.md#ping) | **GET** /ping | Liveness check



## health

> models::PingResponse health()
Dependency health check

Checks the health of all dependent services concurrently: - **vultiserver**: HTTP GET to `http://vultiserver:8080/ping` - **networking**: HTTP GET to `http://networking:8080/health` - **redis**: TCP PING command to `redis:6379`  Returns 200 when all dependencies are healthy, 503 when any dependency is unhealthy. 

### Parameters

This endpoint does not need any parameter.

### Return type

[**models::PingResponse**](PingResponse.md)

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: application/json

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)


## ping

> String ping()
Liveness check

Returns a simple \"pong\" response indicating the service is running.

### Parameters

This endpoint does not need any parameter.

### Return type

**String**

### Authorization

No authorization required

### HTTP request headers

- **Content-Type**: Not defined
- **Accept**: text/plain

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

