## Outbound Traffic Report

_(no communication)_


<details>
<summary>💬 Communication details</summary>

```
✅ 00:05.000: HTTPS a.example.com:443 -> (1.0KB)
🚫 00:07.000: HTTPS bad.example.com:443 -> https-not-allowed
ℹ️ 00:08.000: DNS SRV _http._tcp.a.example.com -> no data (SRV is never served)
⚠️ 00:11.000: HTTPS c.example.com:443 -> dns-failed
```

</details>

<sub>*Note: HTTP rules are based on the Host header, HTTPS rules on SNI, and IP rules on the destination IP address.*</sub>

*Reported by [buildcage/isolated-run](https://github.com/buildcage/isolated-run)*

<hr>
