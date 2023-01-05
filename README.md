# GOLB

A loadbalancer written entirely in go

## Features

- [x] Round robin distribution
- [x] Randomized distribution
- [ ] Context aware (checks if server completed a response)
- [ ] Context aware (Utilization - CPU/Memory) _(Requires Client)_
- [ ] Generate SSL certificate for a domain
- [ ] Sticky sessions
- [x] Copy request to client instead of redirecting
- [x] Host based routing
- [x] Health check
- [ ] Request logger
- [ ] Rate limiter
- [ ] Graphana metrics chart for history
- [ ] Graph of currently available hosts with live stream when a request is sent
- [ ] Helm chart

## License

### MIT LICENSE
