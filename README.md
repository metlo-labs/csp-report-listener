<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://storage.googleapis.com/metlo-security-public-images/metlo_logo_horiz_negative%404x.png" height="80">
    <img alt="logo" src="https://storage.googleapis.com/metlo-security-public-images/metlo_logo_horiz%404x.png" height="80">
  </picture>
  <h1 align="center">Metlo CSP Report Listener</h1>
  <p align="center">Easily build your CSP</p>
</p>

---
<div align="center">

[![Prs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=shields)](http://makeapullrequest.com)
[![Join Discord Server](https://img.shields.io/badge/discord%20community-join-blue)](https://discord.gg/4xhumff9BX)
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/metlo-labs/csp-report-listener/deploy-docker.yaml?branch=main)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](/LICENSE)

</div>

---

Building a good CSP is hard to do when you have tons of unknown scripts in your infra.
The easiest way to incrementally build your CSP using the `report-uri` directive and listen for anything that breaks in report only mode.
Our CSP Reporter makes this easy by storing all CSP report logs and displaying distinct reports you can add to your policy.

![UI Screenshot](https://metlo-api-security-public.s3.us-west-2.amazonaws.com/csp-report-listen-screenshot.png)

## Setup

### 1. Install the Service

You can either use Docker or our Binary to install. You can configure the CSP Report listener with the following env vars:

1. **`METLO_SECRET_KEY` [required]** - A secret key to view CSP Reports. **Be sure to set this to something secure!**
2. **`METLO_DATA_PATH` [default `/tmp/metlo_csp/`]** - Where to store CSP Report data. By default we store it in a tmp folder so change this if you want your data to be persisted.
3. **`METLO_PORT` [default 8080]** - The port the service will listen on
4. **`METLO_LOG_LEVEL` [default info]** - Set the logging level to debug

**Docker Setup**

```bash
$ docker run -p 8080:8080 --env METLO_SECRET_KEY=<A_RANDOM_STRING> metlo/csp-service
```

**Binary Setup**

```bash
$ curl https://metlo-releases.s3.us-west-2.amazonaws.com/csp_service_linux_amd64_latest > metlo_csp_service
$ chmod +x metlo_csp_service
$ METLO_SECRET_KEY=<A_RANDOM_STRING> ./metlo_csp_service
```

Be sure to deploy this service behind a public endpoint so your site can send reports to it. Ping us on [discord](https://discord.gg/4xhumff9BX) if you have any questions!

### 2. Configure Headers

Add the following directive to your CSP Header:

```
report-uri <METLO_CSP_SERVICE_DOMAIN>
```

For example your CSP Header might look like this:

```
Content-Security-Policy: default-src 'self'; script-src https://example.com; report-uri <METLO_CSP_SERVICE_DOMAIN>
```

If you only want to report violations use the following:

```
Content-Security-Policy-Report-Only: report-uri <METLO_CSP_SERVICE_DOMAIN>;
```