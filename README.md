# ClouDyn

ClouDyn is a simple web application to implement CloudFlare dynamic DNS updates via the Dyn DNS API.

A hosted version of ClouDyn is available at the following address:

https://cloudyn.luphy.net

This is hosted on the Heroku free tier, so it will likely take a few seconds for the initial request to complete.

# Table of Contents

- [Overview](#overview)
- [Disclaimers and Notes](#disclaimers-and-notes)
- [Usage](#usage)
  * [Update](#update)
    + [Configuration](#configuration)
    + [Return Codes](#return-codes)
    + [Examples](#examples)
  * [Check IP](#check-ip)
- [Running the Server](#running-the-server)
  * [Installation](#installation)
  * [Configuration](#configuration-1)

# Overview

The purpose of this service is to provide a translation layer that allows for updating CloudFlare DNS records using the "standard" Dynamic DNS API available in popular clients such as [ddclient](https://ddclient.sf.net).

Dynamic DNS is important for environments where the IP is not static, such as on a residential connection. Because of this, there are several services which provide the ability to dynamically update a hostname with a new IP address. The most prominent of which is [Dyn](https://dyn.com/) who created the initial API specification for dynamic DNS updates. This API has been re-implemented for competing services and is also the standard API which DDNS clients use on popular router firmwares such as DD-WRT.

The official Dyn API documentation can be found below:

* [API](https://help.dyn.com/remote-access-api/perform-update/)
* [Return Codes](https://help.dyn.com/remote-access-api/return-codes/)
* [Check IP](https://help.dyn.com/remote-access-api/checkip-tool/)

Unfortunately, there are not many free DNS providers which provide Dynamic DNS. CloudFlare is a notable exception, which provides this service in addition with many other great things such as transparent CDN and SSL termination. However, they do not implement the Dyn Dynamic DNS API, instead opting to make it a part of their own larger CloudFlare API.

# Disclaimers and Notes

The official Dyn DNS service provides rate-limiting functionality in order to prevent excessive DNS updates. This is NOT implemented by ClouDyn. Because the API key is provided by the client, any abuse will be counted against the requester's CloudFlare account.

In addition, it should be noted that the CloudFlare API key is incredibly sensitive. While I have taken as many steps as possible to ensure the hosted version of ClouDyn does not log this data, it is recommended that you run this yourself if you are concerned about the API key leaking out.

Many of the Dyn return codes provided by this service are "best guess" based on the official documentation and are not expected to match 1-1 with the Dyn DNS service. Please open an issue if this is causing an issue with a particular client.

The hosted version is provided with absolutely no SLA whatsoever. I will update the README in the event that it is taken down. However, feel free to deploy it to Heroku yourself!

# Usage

## Update

The `/update` route is used for performing Dynamic DNS updates.

### Configuration

First, authentication information for CloudFlare needs to be provided. This can either be done via HTTP basic auth or via GET parameters.

Additional configiuration information is provided via standard GET parameters:

| Name | Description |
|---|---|
| hostname | Hostname in CloudFlare to update with the new IP address |
| myip | IP address to use in the update. If not provided, it will be determined from request data |
| 
| email | CloudFlare E-Mail, if not using basic auth
| key | CloudFlare API Key, if not using basic auth

### Return Codes

After a successful update, the server will return one of two codes:

| Name | Description |
|---|---|
| ok (ip) | DNS record was successfully updated to the IP returned |
| nochg (ip) | IP returned is the same as the current one in CloudFlare, so no update occurred |

The following Dyn return codes can be returned by the server in the event of an error:

| Name | Description |
|---|---|
| notfqdn | Hostname provided is either invalid or does not exist in the CloudFlare account |
| badauth | Authentication information is missing or invalid. Also returns HTTP 401 Unauthorized |
| badip | IP address provided is not a valid address |
| dnserr | An unexpected error was encountered while interacting with the CF API. The error is logged server-side |

### Examples

Update the test.example.com host to the public IP address of the requesting machine, using E-Mail test@example.com and Key ABC123 via basic auth:

```
curl https://test@example.com:ABC123@cloudyn.luphy.net/update?hostname=test.luphy.net
ok 203.0.113.1
```

Update the test.example.com host to the public IP address of the requesting machine, using E-Mail test@example.com and Key ABC123 via GET parameters:

```
curl https://cloudyn.luphy.net/update?hostname=test.luphy.net&email=luphytwo@gmail.com&key=ABC123
ok 203.0.113.1
```

Update the test.example.com host to the IP 203.0.113.1 directly, using E-Mail test@example.com and Key ABC123 via basic auth:

```
curl https://test@example.com:ABC123@cloudyn.luphy.net/update?hostname=test.luphy.net&myip=203.0.113.1
ok 203.0.113.1
```

## Check IP

The `/checkip` route implements the Dyn Check IP specification. It is used in the event that a client is unable to determine it's public IP, and must rely on an external check.

To use this route, simply perform a GET:

```
curl https://cloudyn.luphy.net/checkip
<html><head><title>Current IP Check</title></head><body>Current IP Address: 203.0.113.1</body></html>
```

This determines the requester's IP address in the following order of precedence (high-to-low):

* Remote Addr of the HTTP request
* X-Forwarded-For header - Used by many reverse proxies
* Client-IP header - Listed in the Dyn specification
* CF-Connecting-IP - IP of the requesting user provided by CloudFlare

In the event that it is unable to determine an IP, it will provide an error message:

```
curl https://cloudyn.luphy.net/checkip
<html><head><title>Current IP Check</title></head><body>Unable to determine IP</body></html>
```

# Running the Server

## Installation

ClouDyn is installed like any other Go package:

`go get github.com/adammillerio/cloudyn`

This will make the `cloudyn` binary available in `$GOPATH/bin`

## Configuration

The web server itself has minimal configuration options that are set via environment variables:

| Name  | Default  | Description  |
|---|---|---|
| PORT | N/A | Used by Heroku to indicate listen port, overrides CLOUDYN_ADDR |
| CLOUDYN_ADDR | :8080 | Address and Port for the server to bind to |
| CLOUDYN_LOG_LEVEL | info | Log level, can be debug, info, warn, or error |
| CLOUDYN_DISABLE_ACCESS_LOGS | false | Whether or not to disable access logs |

After setting environment variables, it can be ran by invoking `cloudyn`.
