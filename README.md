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
- [ ] TCP Loadbalancing
- [ ] UDP Loadbalancing
- [ ] Request logger
- [x] Rate limiter
- [ ] Graphana metrics chart for history
- [ ] Graph of currently available hosts with live stream when a request is sent
- [ ] Helm chart

\
\
\
\
\
\
\
<br />

## License

Copyright (c) 2023, Omar Waleed Ezzat

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

Commercial Use

Commercial use of the Software is prohibited without the prior written consent of Omar Waleed Ezzat. Commercial use includes, but is not limited to, the use of the Software to:

Generate revenue;
Sell products or services;
Provide services to third parties; or
Use the Software in a business environment.
If you wish to use the Software for commercial purposes, please contact Omar Waleed Ezzat at <owezzat@gmail.com>
