package com.security.idsips.sensor;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.EtherType;
import org.pcap4j.packet.namednumber.IpNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import java.net.InetAddress;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Network sensor service for capturing and analyzing network packets
 */
@Service
public class NetworkSensorService {
    
    private static final Logger logger = LoggerFactory.getLogger(NetworkSensorService.class);
    
    @Value("${idsips.sensor.enabled:true}")
    private boolean sensorEnabled;
    
    @Value("${idsips.sensor.interface:any}")
    private String networkInterface;
    
    @Value("${idsips.sensor.capture-timeout:1000}")
    private int captureTimeout;
    
    @Value("${idsips.sensor.buffer-size:65536}")
    private int bufferSize;

    @Value("${idsips.sensor.simulation.enabled:true}")
    private boolean simulationEnabled;

    @Value("${idsips.sensor.simulation.packet-interval:5000}")
    private int simulationPacketInterval;

    @Value("${idsips.sensor.max-packet-size:1500}")
    private int maxPacketSize;

    @Value("${idsips.sensor.min-packet-size:64}")
    private int minPacketSize;

    @Value("${idsips.sensor.simulation.generate-alerts:true}")
    private boolean generateAlerts;
    
    private PcapHandle pcapHandle;
    private final AtomicBoolean isCapturing = new AtomicBoolean(false);
    private final BlockingQueue<NetworkPacket> packetQueue = new LinkedBlockingQueue<>();
    private int simulationCounter = 0;
    
    @Autowired
    private PacketAnalysisService packetAnalysisService;
    
    @PostConstruct
    public void init() {
        if (sensorEnabled) {
            try {
                initializeCapture();
                // Start capture in a separate thread to avoid blocking Spring Boot startup
                Thread captureThread = new Thread(() -> {
                    try {
                        startCapture();
                    } catch (Exception e) {
                        logger.error("Error in packet capture thread", e);
                    }
                });
                captureThread.setDaemon(true);
                captureThread.setName("PacketCapture");
                captureThread.start();
                logger.info("Network sensor initialized and started");
            } catch (Exception e) {
                logger.error("Failed to initialize network sensor", e);
                // Continue without packet capture in case of permission issues
                if (simulationEnabled) {
                    logger.warn("Running in simulation mode - generating sample traffic");
                    startSimulationMode();
                } else {
                    logger.warn("Packet capture failed and simulation is disabled");
                }
            }
        } else {
            logger.info("Network sensor is disabled");
        }
    }
    
    @PreDestroy
    public void cleanup() {
        stopCapture();
        if (pcapHandle != null && pcapHandle.isOpen()) {
            pcapHandle.close();
        }
        logger.info("Network sensor stopped and cleaned up");
    }
    
    /**
     * Initialize packet capture
     */
    private void initializeCapture() throws PcapNativeException, org.pcap4j.core.NotOpenException {
        PcapNetworkInterface nif;
        
        if ("any".equals(networkInterface)) {
            // Try to find the first available network interface
            nif = Pcaps.getDevByName("any");
            if (nif == null) {
                // Fallback to first available interface
                var devices = Pcaps.findAllDevs();
                if (!devices.isEmpty()) {
                    nif = devices.get(0);
                    logger.info("Using network interface: {}", nif.getName());
                } else {
                    throw new PcapNativeException("No network interfaces found");
                }
            }
        } else {
            nif = Pcaps.getDevByName(networkInterface);
            if (nif == null) {
                throw new PcapNativeException("Network interface not found: " + networkInterface);
            }
        }
        
        pcapHandle = nif.openLive(bufferSize, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, captureTimeout);
        
        // Set filter to capture TCP and UDP traffic
        pcapHandle.setFilter("tcp or udp", BpfProgram.BpfCompileMode.OPTIMIZE);
    }
    
    /**
     * Start packet capture (runs in separate thread)
     */
    public void startCapture() {
        if (pcapHandle == null || isCapturing.get()) {
            return;
        }
        
        isCapturing.set(true);
        logger.info("Starting packet capture...");
        
        try {
            pcapHandle.loop(-1, new PacketListener() {
                @Override
                public void gotPacket(Packet packet) {
                    if (!isCapturing.get()) {
                        return;
                    }
                    
                    try {
                        NetworkPacket networkPacket = parsePacket(packet);
                        if (networkPacket != null) {
                            packetQueue.offer(networkPacket);
                            // Process packet asynchronously
                            packetAnalysisService.analyzePacket(networkPacket);
                        }
                    } catch (Exception e) {
                        logger.debug("Error parsing packet: {}", e.getMessage());
                    }
                }
            });
        } catch (Exception e) {
            logger.error("Error during packet capture", e);
        } finally {
            isCapturing.set(false);
        }
    }
    
    /**
     * Stop packet capture
     */
    public void stopCapture() {
        if (isCapturing.get()) {
            isCapturing.set(false);
            if (pcapHandle != null) {
                try {
                    pcapHandle.breakLoop();
                } catch (Exception e) {
                    logger.debug("Error stopping capture: {}", e.getMessage());
                }
            }
            logger.info("Packet capture stopped");
        }
    }
    
    /**
     * Parse captured packet into NetworkPacket object
     */
    private NetworkPacket parsePacket(Packet packet) {
        try {
            EthernetPacket ethernetPacket = packet.get(EthernetPacket.class);
            if (ethernetPacket == null || ethernetPacket.getHeader().getType() != EtherType.IPV4) {
                return null;
            }
            
            IpV4Packet ipPacket = packet.get(IpV4Packet.class);
            if (ipPacket == null) {
                return null;
            }
            
            NetworkPacket networkPacket = new NetworkPacket();
            networkPacket.setSourceIp(ipPacket.getHeader().getSrcAddr().getHostAddress());
            networkPacket.setDestinationIp(ipPacket.getHeader().getDstAddr().getHostAddress());
            networkPacket.setPacketSize(packet.length());
            networkPacket.setRawData(packet.toString());
            
            // Parse TCP/UDP specific information
            if (ipPacket.getHeader().getProtocol() == IpNumber.TCP) {
                TcpPacket tcpPacket = packet.get(TcpPacket.class);
                if (tcpPacket != null) {
                    networkPacket.setProtocol("TCP");
                    networkPacket.setSourcePort(tcpPacket.getHeader().getSrcPort().valueAsInt());
                    networkPacket.setDestinationPort(tcpPacket.getHeader().getDstPort().valueAsInt());
                    
                    // Extract payload if available
                    Packet payload = tcpPacket.getPayload();
                    if (payload != null) {
                        networkPacket.setPayload(payload.toString());
                    }
                }
            } else if (ipPacket.getHeader().getProtocol() == IpNumber.UDP) {
                UdpPacket udpPacket = packet.get(UdpPacket.class);
                if (udpPacket != null) {
                    networkPacket.setProtocol("UDP");
                    networkPacket.setSourcePort(udpPacket.getHeader().getSrcPort().valueAsInt());
                    networkPacket.setDestinationPort(udpPacket.getHeader().getDstPort().valueAsInt());
                    
                    // Extract payload if available
                    Packet payload = udpPacket.getPayload();
                    if (payload != null) {
                        networkPacket.setPayload(payload.toString());
                    }
                }
            }
            
            return networkPacket;
            
        } catch (Exception e) {
            logger.debug("Error parsing packet: {}", e.getMessage());
            return null;
        }
    }
    
    /**
     * Start simulation mode for testing when real packet capture is not available
     */
    @Async
    private void startSimulationMode() {
        logger.info("Starting network traffic simulation...");
        
        new Thread(() -> {
            while (sensorEnabled) {
                try {
                    // Generate sample network packets for testing
                    NetworkPacket simulatedPacket = generateSimulatedPacket();
                    packetQueue.offer(simulatedPacket);
                    packetAnalysisService.analyzePacket(simulatedPacket);
                    
                    Thread.sleep(simulationPacketInterval); // Generate packet at configured interval
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    logger.debug("Error in simulation mode: {}", e.getMessage());
                }
            }
        }).start();
    }
    
    /**
     * Generate simulated network packet for testing
     */
    private NetworkPacket generateSimulatedPacket() {
        String[] sourceIps = {"192.168.1.100", "10.0.0.50", "172.16.0.25", "192.168.1.200"};
        String[] destIps = {"8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"};
        String[] protocols = {"TCP", "UDP"};
        int[] ports = {80, 443, 22, 21, 25, 53, 8080, 3389};
        
        NetworkPacket packet = new NetworkPacket();
        packet.setSourceIp(sourceIps[(int) (Math.random() * sourceIps.length)]);
        packet.setDestinationIp(destIps[(int) (Math.random() * destIps.length)]);
        packet.setProtocol(protocols[(int) (Math.random() * protocols.length)]);
        packet.setSourcePort((int) (Math.random() * 65535));
        packet.setDestinationPort(ports[(int) (Math.random() * ports.length)]);
        packet.setPacketSize((int) (Math.random() * (maxPacketSize - minPacketSize)) + minPacketSize);
        packet.setPayload("Simulated packet payload");
        
        return packet;
    }
    
    /**
     * Get current packet queue size
     */
    public int getQueueSize() {
        return packetQueue.size();
    }
    
    /**
     * Check if sensor is currently capturing
     */
    public boolean isCapturing() {
        return isCapturing.get();
    }
}
