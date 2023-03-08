# ssl_socket

The purpose of this repo is to interact with HTTPS API endpoints to get information available on the internet using the c programming language. 
This code is capable of interacting servers implementing the HTTPS protocol. 

## Compiling
Installation of the [OpenSSL](https://www.openssl.org) library is necessary. 

```
gcc -l ssl -l crypto main.c
```

## Usage
```c
char *host = "api.fiscaldata.treasury.gov\0";
char *endpt = "/services/api/fiscal_service/v1/accounting/od/schedules_fed_debt_daily_activity?filter=record_date:eq:2022-05-01\0"; 
int err = ssl(host, endpt);
if(err < 0) {
  fprintf(stderr, "ssl failed\n");
  return -1; 
}
```
