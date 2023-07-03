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
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/metlo-labs/csp-report-listener/build.yml?branch=main)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](/LICENSE)

</div>

---

Building a good CSP is hard to do when you have tons of unknown scripts in your infra.
The easiest way to incrementally build your CSP using the `report-uri` directive and listen for anything that breaks in report only mode.
Our CSP Reporter makes this easy by storing all CSP report logs and displaying distinct reports you can add to your policy.
