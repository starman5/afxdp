import matplotlib.pyplot as plt

afxdp_xvalues = [0.28, 0.44, 0.73, 1.14, 1.53, 1.71, 2.12, 2.23, 2.35, 2.37, 2.38]
afxdp_yvalues = [22, 22, 24, 33, 37, 45, 55, 70, 84, 103, 107]

udp_xvalues = [0.04, 0.06, 0.1, 0.154, 0.201, 0.242, 0.263, 0.281, 0.284]
udp_yvalues = [22, 22, 24, 26, 31, 40, 55, 80, 102]

plt.plot(afxdp_xvalues, afxdp_yvalues, label="af_xdp")
plt.plot(udp_xvalues, udp_yvalues, label="udp")

plt.yticks(range(0, 201, 25))
plt.xticks([i/4 for i in range(11)])

plt.title("Throughput Latency Curve")
plt.xlabel("Throughput (mops)")
plt.ylabel("Latency (microseconds)")
plt.legend()

plt.savefig("plt.png")