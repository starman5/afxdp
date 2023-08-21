import matplotlib.pyplot as plt

afxdp_xvalues = [0, 1, 2]
afxdp_yvalues = [0, 2.32, 4.71]

udp_xvalues  = [0, 1, 2]
udp_yvalues = [0, 0.285, 0.451]


plt.plot(afxdp_xvalues, afxdp_yvalues, label="af_xdp")
plt.plot(udp_xvalues, udp_yvalues, label="udp")

plt.yticks(range(0, 6, 1))
plt.xticks(range(0, 3, 1))

plt.title("Throughput Based on Number of Cores")
plt.xlabel("Cores")
plt.ylabel("Throughput (mops)")
plt.legend()

plt.savefig("throughputplt.png")