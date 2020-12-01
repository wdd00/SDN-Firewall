## Rules:
Block all traffic between h1 and h2

Block IMCP traffic from any hosts to h4

Block HTTP traffic from h3 to h4

## Execution steps:
1. Use mininet to simulate the network.
```sudo mn --controller=remote,ip=127.0.0.1 --mac -i 10.1.1.0/24 --switch=ovsk,protocols=OpenFlow13 --topo=single,4```

2. start web server in host4
```python -m SimpleHTTPServer 80```

3. Run the application by using Ryu
```ryu-manager myapp.py```
