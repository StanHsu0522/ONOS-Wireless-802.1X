/*
 * Copyright 2022-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package nctu.winlab.eapsniffer;

import org.onlab.packet.Ethernet;
import org.onlab.packet.IPv4;
import org.onlab.packet.IpAddress;
import org.onlab.packet.MacAddress;
import org.onlab.packet.RADIUS;
import org.onlab.packet.RADIUSAttribute;
import org.onlab.packet.UDP;
import org.onosproject.cfg.ComponentConfigService;
import org.onosproject.core.ApplicationId;
import org.onosproject.core.CoreService;
import org.onosproject.net.ConnectPoint;
import org.onosproject.net.PortNumber;
import org.onosproject.net.flow.DefaultTrafficSelector;
import org.onosproject.net.flow.DefaultTrafficTreatment;
import org.onosproject.net.flow.TrafficSelector;
import org.onosproject.net.flow.TrafficTreatment;
import org.onosproject.net.packet.DefaultOutboundPacket;
import org.onosproject.net.packet.InboundPacket;
import org.onosproject.net.packet.OutboundPacket;
import org.onosproject.net.packet.PacketContext;
import org.onosproject.net.packet.PacketPriority;
import org.onosproject.net.packet.PacketProcessor;
import org.onosproject.net.packet.PacketService;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import static org.onlab.util.Tools.get;

/**
 * Skeletal ONOS application component.
 */
@Component(immediate = true,
           service = {EapSnifferService.class},
           property = {
               "someProperty=Some Default String Value",
           })
public class EapSnifferManager 
        implements EapSnifferService {
    
    private static final String APP_NAME = "nctu.winlab.eapsniffer";
    private static final String RADIUS_SERVER_IP = "192.168.44.128";
    private static final int RADIUS_AUTH_PORT = 1812;
    private static final ConnectPoint RADIUS_SERVER_CONNCECT_POINT = ConnectPoint.fromString​("of:000078321bdf7000/12");
    private static final ConnectPoint AP_AUTHENTICATOR_CONNCECT_POINT = ConnectPoint.fromString​("of:000078321bdf7000/13");

    /** Some configurable property. */
    private String someProperty;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected ComponentConfigService cfgService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected CoreService coreService;
    
    @Reference(cardinality = ReferenceCardinality.MANDATORY)
    protected PacketService packetService;

    private final Logger log = LoggerFactory.getLogger(getClass());

    // our unique identifier
    private ApplicationId appId;

    // our application-specific event handler
    private ReactivePacketProcessor processor = new ReactivePacketProcessor();

    // for matching access-accept with access-request
    private Map<Byte, Supplicant>outgoingPacketMap = new HashMap<>();

    @Activate
    protected void activate() {
        appId = coreService.registerApplication(APP_NAME);
        cfgService.registerProperties(getClass());
        packetService.addProcessor(processor, PacketProcessor.director(2));
        requestIntercepts();

        log.info("Started");
    }

    @Deactivate
    protected void deactivate() {
        withdrawIntercepts();
        packetService.removeProcessor(processor);
        cfgService.unregisterProperties(getClass(), false);

        log.info("Stopped");
    }

    @Modified
    public void modified(ComponentContext context) {
        Dictionary<?, ?> properties = context != null ? context.getProperties() : new Properties();
        if (context != null) {
            someProperty = get(properties, "someProperty");
        }
        log.info("Reconfigured");
    }

    @Override
    public void someMethod() {
        log.info("Invoked");
    }

    private void requestIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.requestPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void withdrawIntercepts() {
        TrafficSelector.Builder selector = DefaultTrafficSelector.builder();
        selector.matchEthType(Ethernet.TYPE_IPV4);
        packetService.cancelPackets(selector.build(), PacketPriority.REACTIVE, appId);
    }

    private void sendPacketToDataPlane(Ethernet ethernetPkt, ConnectPoint coonectPt) {
        TrafficTreatment treatment = DefaultTrafficTreatment.builder().setOutput(coonectPt.port()).build();
        OutboundPacket packet = new DefaultOutboundPacket(coonectPt.deviceId(),
                                                          treatment, ByteBuffer.wrap(ethernetPkt.serialize()));
        packetService.emit(packet);
    }

    private class ReactivePacketProcessor implements PacketProcessor {
        @Override
        public void process(PacketContext context) {

            if (context.isHandled()) {
                return;
            }

            // Extract the original Ethernet frame from the packet information
            InboundPacket pkt = context.inPacket();
            Ethernet ethPkt = pkt.parsed();
            if (ethPkt == null) {
                return;
            }

            if (ethPkt.getEtherType() == Ethernet.TYPE_IPV4) {
                IPv4 ip4Pkt = (IPv4) ethPkt.getPayload();
                // IpAddress srcIp = IpAddress.valueOf(ip4Pkt.getSourceAddress());
                // IpAddress dstIp = IpAddress.valueOf(ip4Pkt.getDestinationAddress());

                if (ip4Pkt.getProtocol() == IPv4.PROTOCOL_UDP) {
                    UDP udpPkt = (UDP) ip4Pkt.getPayload();
                    int srcPort = udpPkt.getSourcePort();
                    int dstPort = udpPkt.getDestinationPort();

                    if (srcPort == RADIUS_AUTH_PORT || dstPort == RADIUS_AUTH_PORT) {
                        RADIUS radiusPkt = (RADIUS) udpPkt.getPayload();
                        byte pktId = radiusPkt.getIdentifier();

                        switch (radiusPkt.getCode()) {
                            case RADIUS.RADIUS_CODE_ACCESS_REQUEST:
                                RADIUSAttribute radiusAttrUserName =
                                        radiusPkt.getAttribute(RADIUSAttribute.RADIUS_ATTR_USERNAME);
                                String user_name = null;
                                if (radiusAttrUserName != null) {
                                    user_name = new String(radiusAttrUserName.getValue(), StandardCharsets.UTF_8);
                                }
                                RADIUSAttribute radiusAttrCallingStationId =
                                        radiusPkt.getAttribute(RADIUSAttribute.RADIUS_ATTR_CALLING_STATION_ID);
                                String calling_station_id = null;
                                if (radiusAttrCallingStationId != null) {
                                    calling_station_id = new String(radiusAttrCallingStationId.getValue(), StandardCharsets.UTF_8);
                                    calling_station_id = calling_station_id.replace('-', ':');
                                }
                                outgoingPacketMap.put(pktId, new Supplicant(calling_station_id, user_name));
                                break;

                            case RADIUS.RADIUS_CODE_ACCESS_ACCEPT:
                                Supplicant supAccepted = outgoingPacketMap.get(pktId);
                                if (supAccepted == null) {
                                    log.info("unkown user has been authorized!");
                                }
                                else {
                                    outgoingPacketMap.remove(pktId);
                                    log.info("User '{}' ({}) has been authorized!!!!!!!!!!!!!!!!!",
                                            supAccepted.user_name, supAccepted.mac);
                                }
                                break;

                            case RADIUS.RADIUS_CODE_ACCESS_REJECT:
                                Supplicant supRejected = outgoingPacketMap.get(pktId);
                                if (supRejected == null) {
                                    log.info("unkown user has benn rejected!");
                                }
                                else {
                                    outgoingPacketMap.remove(pktId);
                                    log.info("User '{}' ({}) has been rejected!!!!!!!!!!!!!!!!!",
                                            supRejected.user_name, supRejected.mac);
                                }
                                break;

                            default:
                                    /**
                                     * To do:
                                     * automatically remove stale record in outgoingPacketMap.
                                     * 
                                     * 
                                     */
                                break;
                        }

                        // incoming packet (RADIUS server --> AP Authenticator)
                        if (srcPort == RADIUS_AUTH_PORT) {
                            sendPacketToDataPlane(ethPkt, AP_AUTHENTICATOR_CONNCECT_POINT);
                        }
                        // outgoing packet (AP Authenticator --> RADIUS server)
                        else if (dstPort == RADIUS_AUTH_PORT) {
                            sendPacketToDataPlane(ethPkt, RADIUS_SERVER_CONNCECT_POINT);
                        }
                    }
                }
            }
        }
    }

    private class Supplicant {
        MacAddress mac;
        String user_name;

        Supplicant(String mac, String user_name) {
            this.mac = MacAddress.valueOf(mac);
            this.user_name = user_name;
        }
    }
}
