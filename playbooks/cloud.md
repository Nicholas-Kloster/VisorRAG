# Cloud IP Recon Playbook

## When to use
Target resolves to AWS, GCP, Azure, Cloudflare, Oracle, or other major cloud
provider IP ranges. Cloud-hosted assets have specific recon patterns that
differ from on-prem.

## AWS IP Recon
1. Identify AWS region from IP via published ip-ranges.json mapping. Region
   reveals data residency, latency profile, and likely tenant geography.
2. Reverse DNS often returns ec2-N-N-N-N.region.compute.amazonaws.com or
   ip-N-N-N-N.region.compute.internal — direct attribution to EC2.
3. Probe TLS on 443 without SNI to surface the default certificate. AWS
   Certificate Manager (ACM) certs name the customer; Application Load
   Balancer default certs reveal the LB tier.
4. Check ports 80, 443, 8080, 8443, 9000, 9090, 8888 — common for ALB
   targets, exposed admin UIs, and misconfigured ECS/EKS workloads.
5. ECS metadata endpoint 169.254.170.2 and EC2 IMDSv1 169.254.169.254
   are not reachable externally but worth noting if the probe lands inside
   a misconfigured host.

## GCP IP Recon
1. Reverse DNS commonly returns N.N.N.N.bc.googleusercontent.com.
2. GCP Load Balancer default certs surface project ID and customer name in
   the SAN list — direct OV/EV attribution.
3. Common exposed services: Cloud Run (443), GKE node ports (30000-32767),
   App Engine default domains.
4. Cloud Storage buckets named after the project — check for
   storage.googleapis.com/PROJECT_ID/.

## Cloudflare-fronted
1. CF-RAY header in HTTP responses confirms Cloudflare proxy.
2. Origin IP discovery: censys.io / shodan certificate search for the
   target's TLS cert hash, looking for direct-IP matches outside CF ranges.
3. SSL Labs and crt.sh subdomain enumeration often reveal origin via
   non-proxied subdomains (api., dev., staging.).

## Tooling order
- httpx for HTTP/TLS surface enumeration with -tls-probe -title -tech-detect
- asnmap for ASN attribution
- nuclei with cloud-config templates for misconfigurations
- naabu for top-port sweep before deep dive

## Key references
- AWS: https://ip-ranges.amazonaws.com/ip-ranges.json
- GCP: https://www.gstatic.com/ipranges/cloud.json
- Cloudflare: https://www.cloudflare.com/ips/
