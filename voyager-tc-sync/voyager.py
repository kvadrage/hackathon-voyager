#!/usr/bin/env python

import re
import os
import sys
import signal
import subprocess
import logging
from ipaddr import IPAddress
from collections import OrderedDict
try:
    from nlmanager.nllistener import NetlinkManagerWithListener
    from nlmanager.nlmanager import AF_INET, AF_INET6
    from nlmanager.nlpacket import *
except:
    sys.exit("Can't import nlmanager python library!")

def execute_command(*args):
    command = " ".join(args)
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as e:
        log.error("Error executing command %s: %s" % (command, e))
        return False
    out_text = output.decode('utf-8')
    return out_text

def mac_format(mac):
    mac = mac.translate(None,".:- ").lower()
    return ':'.join(mac[i:i+2] for i in range(0,len(mac),2))

def get_ifindex(ifname):
    output = execute_command("ip link show") or ""
    for line in output.splitlines():
        re_line = re.search(r"^(\d+): %s: " % ifname, line)
        if re_line:
            return int(re_line.group(1))
    return None

def get_port_offloads(ifname):
    offloads = dict()
    output = execute_command("ethtool -k", ifname) or ""
    for line in output.splitlines():
        re_line = re.search(r"^([\w-]+):\s?(on|off)" , line)
        if re_line:
            offloads[re_line.group(1)] = re_line.group(2)
    return offloads

class TCHelper(object):
    def __init__(self):
        self.sb_ingress = 1

    def port_init(self, ifname):
        return execute_command("tc qdisc replace dev %s ingress_block %d clsact" %
                                (ifname, self.sb_ingress)) != False

    def port_fini(self, ifname):
        return execute_command("tc qdisc del dev %s ingress_block %d clsact" %
                                (ifname, self.sb_ingress)) != False

    def tunnel_port_init(self, ifname):
        return execute_command("tc qdisc replace dev %s clsact" % ifname) != False

    def tunnel_port_fini(self, ifname):
        return execute_command("tc qdisc del dev %s clsact" % ifname) != False

    def port_vlan_add(self, idx, ifname, vlan, tagged=False):
        if tagged:
            return execute_command("tc filter add block %d pref %d flower indev %s vlan_id %d action goto chain %d" %
                                (self.sb_ingress, idx, ifname, vlan, vlan)) != False
        else:
            return execute_command("tc filter add block %d pref %d flower indev %s action goto chain %d" %
                                (self.sb_ingress, idx, ifname, vlan)) != False

    def port_vlan_del(self, idx):
        return execute_command("tc filter del block %d pref %d" %
                                (self.sb_ingress, idx)) != False

    def vlan_vrf_add(self, vlan, vrf_table):
        return execute_command("tc filter add block %d chain %d pref 5000 flower action goto chain %d" %
                                (self.sb_ingress, vlan, vrf_table)) != False

    def vlan_vrf_add_remote(self, vrf, vrf_table_remote):
        return execute_command("tc filter add block %d chain %d pref 5000 flower action goto chain %d" %
                                (self.sb_ingress, vrf, vrf_table_remote)) != False

    def vlan_vrf_del(self, vlan):
        return execute_command("tc filter del block %d chain %d pref 5000 flower" %
                                (self.sb_ingress, vlan)) != False

    def tunnel_port_vrf_add(self, ifname, dst_mac, vxlan_id, vxlan_local_ip, vxlan_port, vrf_table):
        return execute_command("tc filter add dev %s ingress protocol ip pref 5000 flower dst_mac %s enc_key_id %d enc_dst_ip %s enc_dst_port %d action goto chain %d" %
                                (ifname, dst_mac, vxlan_id, vxlan_local_ip, vxlan_port, vrf_table)) != False

    def tunnel_port_vrf_del(self, ifname):
        return execute_command("tc filter del dev %s ingress protocol ip pref 5000" % ifname) != False

    def bridge_fdb_add_local(self, vlan, idx, dst_mac, ifname):
        return execute_command("tc filter add block %d chain %d pref %d flower dst_mac %s action mirred egress redirect dev %s" %
                                (self.sb_ingress, vlan, idx, dst_mac, ifname))

    def bridge_fdb_add_remote_encap(self, vlan, idx, dst_mac, ifname, vxlan_id, vxlan_local_ip, vxlan_remote_ip, vxlan_port):
        return execute_command("tc filter add block %d chain %d pref %d flower dst_mac %s action tunnel_key set id %d src_ip %s dst_ip %s dst_port %d pipe action mirred egress redirect dev %s" %
                                (self.sb_ingress, vlan, idx, dst_mac, vxlan_id, vxlan_local_ip, vxlan_remote_ip, vxlan_port, ifname))

    def bridge_fdb_add_remote_decap(self, idx, dst_mac, ifname, vxlan_device, vxlan_id, vxlan_local_ip, vxlan_port):
        return execute_command("tc filter add dev %s ingress pref %d flower dst_mac %s enc_key_id %d enc_dst_ip %s enc_dst_port %d action tunnel_key unset pipe action mirred egress redirect dev %s" %
                                (vxlan_device, idx, dst_mac, vxlan_id, vxlan_local_ip, vxlan_port, ifname))

    def bridge_fdb_del(self, vlan, idx = None):
        if idx:
            return execute_command("tc filter del block %d chain %d pref %d" %
                                    (self.sb_ingress, vlan, idx))
        return execute_command("tc filter del block %d chain %d" %
                                    (self.sb_ingress, vlan))

    def bridge_fdb_del_remote_decap(self, vxlan_device, idx = None):
        if idx:
            return execute_command("tc filter del dev %s ingress pref %d" %
                                    (vxlan_device, idx))
        return execute_command("tc filter del dev %s ingress" % vxlan_device)

    def route_neigh_add(self, vrf_table, idx, proto, dst_ip, src_mac, dst_mac, ifname):
        return execute_command("tc filter add block %d chain %d pref %d protocol %s flower dst_ip %s action pedit ex munge eth src set %s pipe action pedit ex munge eth dst set %s pipe action mirred egress redirect dev %s" %
                                (self.sb_ingress, vrf_table, idx, proto, dst_ip, src_mac, dst_mac, ifname))

    def route_neigh_add_decap(self, vxlan_device, vrf_table, idx, proto, dst_ip, src_mac, dst_mac, ifname):
        return execute_command("tc filter add dev %s ingress chain %d pref %d protocol %s flower dst_ip %s action tunnel_key unset pipe action pedit ex munge eth src set %s pipe action pedit ex munge eth dst set %s pipe action mirred egress redirect dev %s" %
                                (vxlan_device, vrf_table, idx, proto, dst_ip, src_mac, dst_mac, ifname))

    def route_neigh_del(self, vrf_table, idx = None):
        if idx:
            return execute_command("tc filter del block %d chain %d pref %d" %
                                    (self.sb_ingress, vrf_table, idx))
        return execute_command("tc filter del block %d chain %d" %
                                    (self.sb_ingress, vrf_table))

    def route_neigh_del_decap(self, vxlan_device, vrf_table, idx = None):
        if idx:
            return execute_command("tc filter del dev %s ingress chain %d pref %d" %
                                    (vxlan_device, vrf_table, idx))
        return execute_command("tc filter del dev %s ingress chain %d" %
                                    (vxlan_device, vrf_table))

    def route_add_encap(self, vrf_table, idx, proto, dst_ip, src_mac, dst_mac, ifname, vxlan_id, vxlan_local_ip, vxlan_remote_ip, vxlan_port):
        return execute_command("tc filter add block %d chain %d pref %d protocol %s flower dst_ip %s action pedit ex munge eth src set %s pipe action pedit ex munge eth dst set %s pipe action tunnel_key set id %d src_ip %s dst_ip %s dst_port %d pipe action mirred egress redirect dev %s" %
                                (self.sb_ingress, vrf_table, idx, proto, dst_ip, src_mac, dst_mac, vxlan_id, vxlan_local_ip, vxlan_remote_ip, vxlan_port, ifname))

    def route_del(self, vrf_table, idx = None):
        if idx:
            return execute_command("tc filter del block %d chain %d pref %d" %
                                    (self.sb_ingress, vrf_table, idx))
        return execute_command("tc filter del block %d chain %d" %
                                    (self.sb_ingress, vrf_table))

class Voyager(NetlinkManagerWithListener):

    def __init__(self, *args, **kwargs):
        self.ports = dict()
        self.vlans = dict()
        self.fdb = OrderedDict()
        self.neigh = OrderedDict()
        self.routes = OrderedDict()
        self.tc = TCHelper()
        super(Voyager, self).__init__(*args, **kwargs)

    def main(self):

        # This loop has two jobs:
        # - process items on our workq
        # - process netlink messages on our netlinkq, messages are placed there via our NetlinkListener
        while True:

            # Sleep until our alarm goes off...NetlinkListener will set the alarm once it
            # has placed a NetlinkPacket object on our netlinkq. If someone places an item on
            # our workq they should also set our alarm...if they don't it is not the end of
            # the world as we will wake up in 1s anyway to check to see if our shutdown_event
            # has been set.
            self.alarm.wait(1)
            self.alarm.clear()

            if self.shutdown_event.is_set():
                log.info("Voyager: shutting things down")
                self.cleanup()
                break

            while not self.workq.empty():
                (event, options) = self.workq.get()

                if event == 'GET_ALL_LINKS':
                    self.get_all_links()
                elif event == 'GET_ALL_BR_LINKS':
                    self.get_all_br_links()
                elif event == 'GET_ALL_ADDRESSES':
                    self.get_all_addresses()
                elif event == 'GET_ALL_NEIGHBORS':
                    self.get_all_neighbors()
                elif event == 'GET_ALL_FDB_NEIGHBORS':
                    self.get_all_fdb_neighbors()
                elif event == 'GET_ALL_ROUTES':
                    self.get_all_routes()
                elif event == 'SERVICE_NETLINK_QUEUE':
                    self.service_netlinkq()
                else:
                    raise Exception("Unsupported workq event %s" % event)

        self.listener.shutdown_event.set()
        self.listener.join()

    def get_neigh_family(self, neigh):
        if neigh["version"] == 4:
            return AF_INET
        if neigh["version"] == 6:
            return AF_INET6
        return None

    def get_all_fdb_neighbors(self):
        family = socket.AF_BRIDGE
        debug = RTM_GETNEIGH in self.debug

        neighbor = Neighbor(RTM_GETNEIGH, debug, use_color=self.use_color)
        neighbor.flags = NLM_F_REQUEST | NLM_F_DUMP
        neighbor.body = pack('Bxxxii', family, 0, 0)
        neighbor.build_message(self.sequence.next(), self.pid)

        if debug:
            self.debug_seq_pid[(neighbor.seq, neighbor.pid)] = True

        self.tx_nlpacket_get_response(neighbor)

    def cleanup(self):
        # for _, entry in self.fdb.items():
        #     vlan = entry.get("vlan")
        #     if vlan:
        #         self.tc.bridge_fdb_del(vlan)
        for _, port in self.ports.items():
            if port.get("offloaded") == True:
                if port["kind"] == "eth":
                    self.tc_port_vlans_del(port)
                    self.tc.port_fini(port["ifname"])
                elif port["kind"] == "vxlan":
                    self.tc.tunnel_port_fini(port["ifname"])
                log.info("Port %s clear offloads" % port["ifname"])

    def port_offloadable(self, ifname):
        # phys_switch_id = msg.get_attribute_value(msg.IFLA_PHYS_SWITCH_ID)
        # if not phys_switch_id:
        #     return False
        hw_tc_offload = get_port_offloads(ifname).get("hw-tc-offload", "") == "on"
        return hw_tc_offload

    def get_port_vlans(self, msg):
        def vlan_flag_to_string(vlan_flag):
            if vlan_flag & Link.BRIDGE_VLAN_INFO_PVID and vlan_flag & Link.BRIDGE_VLAN_INFO_UNTAGGED:
                return "untagged"
            else:
                return "tagged"

        vlans = dict()
        ifname = msg.get_attribute_value(Link.IFLA_IFNAME)
        ifla_af_spec = msg.get_attribute_value(Link.IFLA_AF_SPEC)
        for (x_type, x_value) in ifla_af_spec.iteritems():
            if x_type == Link.IFLA_BRIDGE_VLAN_INFO:
                for (vlan_flag, vlan_id) in x_value:
                    # We store these in the tuple as (vlan, flag) instead (flag, vlan)
                    # so that we can sort the list of tuples
                    vlans[vlan_id] = vlan_flag_to_string(vlan_flag)
        return vlans
    
    def tc_port_vlans_add(self, port):
        res = True
        for vlan,flag in port["vlans"].items():
            tagged = flag == "tagged"
            if not self.tc.port_vlan_add(port["ifindex"], port["ifname"], vlan, tagged):
                res = False
        return res

    def tc_port_vlans_del(self, port):
        return self.tc.port_vlan_del(port["ifindex"])

    def tc_vlan_vrf_add(self, vlan, vrf_table=1):
        # tc vrf chain for local routing (neighbor) starts from 5000
        # tc vrf chain for remote routing (LPM) starts from 10000
        vrf_local_chain = 5000
        vrf_remote_chain = 10000
        if vrf_table != 1:
             vrf_local_chain += vrf_table
             vrf_remote_chain += vrf_table
        if self.tc.vlan_vrf_add(vlan, vrf_local_chain):
            return self.tc.vlan_vrf_add_remote(vrf_local_chain, vrf_remote_chain)
        return False

    def tc_vlan_vrf_del(self, vlan):
        return self.tc.vlan_vrf_del(vlan)

    def tc_fdb_add(self, entry):
        vlan = entry.get("vlan")
        # ignore if no vlan specified
        if not vlan:
            return
        if entry["type"] == "local":
            log.info("Added local FDB entry (%d): %s %s %d" % 
                    (entry["idx"], entry["ifname"], entry["dst_mac"], entry["vlan"]))
            self.tc.bridge_fdb_add_local(entry["vlan"], entry["idx"], entry["dst_mac"], entry["ifname"])
            # add vxlan decap rule directly to all local FDB entries with the same VLAN as relevant VNIs
            for ifname, port in self.ports.items():
                if port["kind"] == "vxlan" and vlan in port.get("vlans", {}):
                    log.info("Added local FDB entry to VXLAN device (%d): %s => %s %s %d %d" % 
                        (entry["idx"], ifname, entry["ifname"], entry["dst_mac"], entry["vlan"], port["vxlan_id"]))
                    self.tc.bridge_fdb_add_remote_decap(entry["idx"], entry["dst_mac"], entry["ifname"], ifname, port["vxlan_id"], port["vxlan_local_ip"], port["vxlan_port"])
        elif entry["type"] == "vxlan":
            vxlan_remote_ip = entry.get("vxlan_remote_ip")

            # # ignore if no vlan of remote VTEP specified
            # if not (vlan and vxlan_remote_ip):
            #     return

            # ignore Head-end Replication entries
            if entry["dst_mac"] == "00:00:00:00:00:00":
                return
            # add encap rule to generic VF pipeline
            self.tc.bridge_fdb_add_remote_encap(vlan, entry["idx"], entry["dst_mac"], entry["ifname"], entry["vxlan_id"], entry["vxlan_local_ip"], entry["vxlan_remote_ip"], entry["vxlan_port"])
            log.info("Added remote FDB entry (%d): %s %s %d %d %s" % 
                    (entry["idx"], entry["ifname"], entry["dst_mac"], entry["vlan"], entry["vxlan_id"], vxlan_remote_ip))

    def tc_fdb_del(self, entry):
        vlan = entry.get("vlan")
        # ignore if no vlan specified
        if not vlan:
            return
        log.info("Removed FDB entry (%d): %s %s %d" %
                (entry["idx"], entry["ifname"], entry["dst_mac"], vlan))
        self.tc.bridge_fdb_del(vlan, entry["idx"])
        # remove vxlan decap rules from all local FDB entries with the same VLAN as relevant VNIs
        for ifname, port in self.ports.items():
            if port["kind"] == "vxlan" and vlan in port.get("vlans", {}):
                log.info("Removed local FDB entry from VXLAN device (%d): %s %s %d" % 
                    (entry["idx"], port["ifname"], entry["dst_mac"], vlan))
                self.tc.bridge_fdb_del_remote_decap(port["ifname"], entry["idx"])

    def tc_neigh_add(self, entry):
        if entry["type"] == "vxlan":
            return
        proto = "ip"
        vrf_chain = 5000
        if entry["vrf_table"] != 1:
             vrf_chain += entry["vrf_table"]
        if entry["version"] == 6:    
            proto = "ipv6"
        self.tc.route_neigh_add(vrf_chain, entry["idx"], proto, entry["dst_ip"], entry["src_mac"], entry["dst_mac"], entry["fdb_ifname"])
        log.info("Added local neighbor entry (%d): %s %s %d %s" % 
                    (entry["idx"], entry["ifname"], entry["dst_ip"], entry["vrf_table"], entry["fdb_ifname"]))
        # add vxlan decap rule directly to all local neighbor entries with the same VRF as relevant L3 VNIs
        for ifname, port in self.ports.items():
            if port["kind"] == "vxlan" and entry["vrf_table"] == port["vrf_table"]:
                self.tc.route_neigh_add_decap(ifname, vrf_chain, entry["idx"], proto, entry["dst_ip"], entry["src_mac"], entry["dst_mac"], entry["fdb_ifname"])
                log.info("Added local neighbor entry to VXLAN device (%d): %s => %s %s %d %d" % 
                        (entry["idx"], ifname, entry["vrf_table"], entry["dst_ip"], entry["vrf_table"], port["vxlan_id"]))

    def tc_neigh_del(self, entry):
        proto = "ip"
        vrf_chain = 5000
        if entry["vrf_table"] != 1:
             vrf_chain += entry["vrf_table"]
        if entry["version"] == 6:    
            proto = "ipv6"
        self.tc.route_neigh_del(vrf_chain, entry["idx"])
        log.info("Removed local neighbor entry (%d): %s %s %d %s" % 
                    (entry["idx"], entry["ifname"], entry["dst_ip"], entry["vrf_table"], entry["fdb_ifname"]))
        # remove vxlan decap rule directly to all local neighbor entries with the same VRF as relevant L3 VNIs
        for ifname, port in self.ports.items():
            if port["kind"] == "vxlan" and entry["vrf_table"] == port["vrf_table"]:
                self.tc.route_neigh_del_decap(ifname, vrf_chain, entry["idx"])
                log.info("Removed local neighbor entry to VXLAN device (%d): %s => %s %s %d %d" % 
                        (entry["idx"], ifname, entry["vrf_table"], entry["dst_ip"], entry["vrf_table"], port["vxlan_id"]))  

    def tc_route_add(self, entry):
        proto = "ip"
        vrf_chain_remote = 10000
        if entry["vrf_table"] != 1:
             vrf_chain_remote += entry["vrf_table"]
        if entry["version"] == 6:    
            proto = "ipv6"
        print("ROUTE ADD: ", entry)
        self.tc.route_add_encap(vrf_chain_remote, entry["idx"], proto, entry["dst_ip"], entry["src_mac"], entry["dst_mac"], entry["ifname"], entry["vxlan_id"], entry["vxlan_local_ip"], entry["vxlan_remote_ip"], entry["vxlan_port"])
        log.info("Added remote encap route entry (%d): %s %s %d %s" % 
                    (entry["idx"], entry["ifname"], entry["dst_ip"], entry["vrf_table"], entry["vxlan_remote_ip"]))

    def get_l3vni_vxlan(self, vlan_port):
        """ Returns L3VNI VXLAN port (VNI) for specific VLAN port
        Tries to find relevant VXLAN port with PVID == VLAN port VLAN_ID
        """
        if vlan_port["kind"] == "vlan":
            vlan = vlan_port["vlan_id"]
            for ifname, port in self.ports.items():
                vlans = port.get("vlans")
                if vlans and port["kind"] == "vxlan" and vlan in vlans and vlans[vlan] == "untagged":
                    return port
        return None

    def get_l3vni_vlan(self, vxlan_port):
        """ Returns L3VNI VLAN port for specific VXLAN port (VNI)
        Tries to find relevant VLAN port with VLAN-ID == VXLAN port PVID
        """
        if vxlan_port["kind"] == "vxlan":
            pvid = None
            vlans = vxlan_port.get("vlans", {})
            for vlan_id, vlan_flag in vlans.items():
                if vlan_flag == "untagged":
                    pvid = vlan_id
                    break
            for ifname, port in self.ports.items():
                if port["kind"] == "vlan" and port["vlan_id"] == pvid:
                    return port
        return None

    def update_l3vni_mapping(self, port):
        vrf_chain = 5000
        if port["kind"] == "vlan":
            # try to relevant vxlan port for the vlan port
            vxlan_port = self.get_l3vni_vxlan(port)
            # map only ports in non-default VRF
            if vxlan_port:
                vxlan_port_ifname = vxlan_port["ifname"]
                vxlan_port_vrf_table = vxlan_port["vrf_table"]
                # map only ports in non-default VRF
                if port["vrf_table"] != 1:
                    port.update({ "vxlan_port": vxlan_port_ifname })
                    vxlan_old_vrf_table = vxlan_port.get("vrf_table")
                    if vxlan_old_vrf_table != 1 and vxlan_old_vrf_table != port["vrf_table"]:
                        # remove the old VRF chain if it's need to be changed
                        self.tc.tunnel_port_vrf_del(vxlan_port_ifname)
                        log.info("VXLAN port %s is deassociated from VRF %d" % (vxlan_port_ifname, vxlan_old_vrf_table))
                    vxlan_vlan_port = vxlan_port.get("vlan_port")
                    if vxlan_vlan_port != port["ifname"]:
                        vxlan_port.update({ "vlan_port": port["ifname"] })
                        vxlan_port.update({ "vrf_table": port["vrf_table"] })
                        vrf_chain += port["vrf_table"]
                        self.tc.tunnel_port_vrf_add(vxlan_port_ifname, port["mac"], vxlan_port["vxlan_id"], vxlan_port["vxlan_local_ip"], vxlan_port["vxlan_port"], vrf_chain)
                        log.info("VXLAN port %s is associated with VLAN port %s (VRF %d)" % (vxlan_port_ifname, port["ifname"], vxlan_port["vrf_table"]))
        elif port["kind"] == "vxlan":
            # try to relevant vlan port for the vxlan port
            vlan_port = self.get_l3vni_vlan(port)
            if vlan_port:
                vlan_port_ifname = vlan_port["ifname"]
                vlan_port_vrf_table = vlan_port["vrf_table"]
                # map only ports in non-default VRF
                if vlan_port_vrf_table != 1:
                    # associate vlan port with vxlan port
                    vlan_port.update({ "vxlan_port": port["ifname"] })
                    vxlan_old_vrf_table = port.get("vrf_table")
                    if vxlan_old_vrf_table != 1 and vxlan_old_vrf_table != port["vrf_table"]:
                        # remove the old VRF chain if it's need to be changed
                        self.tc.tunnel_port_vrf_del(port["ifname"] )
                        log.info("VXLAN port %s is deassociated from VRF %d" % (port["ifname"] , vxlan_old_vrf_table))
                    vxlan_vlan_port = port.get("vlan_port")
                    if vxlan_vlan_port != vlan_port_ifname:
                        port.update({ "vlan_port": vlan_port_ifname })
                        port.update({ "vrf_table": vlan_port_vrf_table })
                        vrf_chain += vlan_port_vrf_table
                        self.tc.tunnel_port_vrf_add(port["ifname"], vlan_port["mac"], vlan_port["vxlan_id"], vlan_port["vxlan_local_ip"], vlan_port["vxlan_port"], vrf_chain)
                        log.info("VXLAN port %s is associated with VLAN port %s (VRF %d)" % (port["ifname"], vlan_port_ifname, vlan_port["vrf_table"]))
        return

    def rx_rtm_newlink(self, msg):
        ifname = msg.get_attribute_value(msg.IFLA_IFNAME)
        ifindex = get_ifindex(ifname)
        ifmac = mac_format(msg.get_attribute_value(msg.IFLA_ADDRESS))
        port = self.ports.get(ifname, {"kind": "unknown"})
        port.update({
            "ifname": ifname,
            "ifindex": ifindex,
            "mac": ifmac,
            "vrf_table": 1,
            "neighbors": OrderedDict()
        })
        if msg.family == AF_BRIDGE:
            vlans = self.get_port_vlans(msg)
            port.update({
                "vlans": vlans,
            })
            if self.port_offloadable(ifname):
                port.update({ "kind": "eth" }) 
            if port["kind"] == "eth" and self.tc.port_init(ifname):
                    port.update({ "offloaded": True }) 
                    if vlans and self.tc_port_vlans_add(port):
                        log.info("Port %s (bridged) is added as tc-offloaded with vlan chains set" % ifname)
                    else:
                        log.info("Port %s (bridged) is added as tc-offloaded" % ifname)
            elif port["kind"] == "vxlan":
                if not port.get("offloaded") and self.tc.tunnel_port_init(ifname):
                    port.update({ "offloaded": True })
                if port.get("offloaded"):
                    log.info("VXLAN port %s (bridged) is added as tc-offloaded" % ifname)
            else:
                log.info("Port %s (bridged) is added" % ifname)

        elif msg.family == AF_UNSPEC:
            link_info = msg.get_attribute_value(Link.IFLA_LINKINFO)
            if link_info:
                if link_info.get(Link.IFLA_INFO_KIND) == "vlan":
                    vlan_data = link_info.get(Link.IFLA_INFO_DATA)
                    # offload only 802.1q
                    if vlan_data and vlan_data.get(Link.IFLA_VLAN_PROTOCOL) == "802.1Q":
                        vlan_id = vlan_data.get(Link.IFLA_VLAN_ID)
                        vrf_table = 1
                        vlan = self.vlans.get(vlan_id, {})
                        slave_data = link_info.get(Link.IFLA_INFO_SLAVE_DATA)
                        if slave_data and link_info.get(Link.IFLA_INFO_SLAVE_KIND) == "vrf":
                            vrf_table = slave_data.get(Link.IFLA_VRF_TABLE)

                        if vlan:
                            if vlan["vrf_table"] != vrf_table:
                                self.tc_vlan_vrf_del(vlan_id)
                                self.tc_vlan_vrf_add(vlan_id, vrf_table)
                                log.info("VLAN %d updated VRF table from %d to %s" % (vlan_id, vlan["vrf_table"], vrf_table))
                        else:
                            self.tc_vlan_vrf_add(vlan_id, vrf_table)
                            log.info("VLAN %d set VRF table to %d" % (vlan_id, vrf_table))
                        self.vlans[vlan_id] = vlan
                        port.update({
                            "kind": "vlan",
                            "vlan_id": vlan_id,
                            "vrf_table": vrf_table,
                            "offloaded": True
                        })

                elif link_info.get(Link.IFLA_INFO_KIND) == "vxlan":
                    vxlan_data = link_info.get(Link.IFLA_INFO_DATA)
                    if vxlan_data:
                        port.update({
                            "kind": "vxlan",
                            "vxlan_id": vxlan_data.get(Link.IFLA_VXLAN_ID),
                            "vxlan_local_ip": str(vxlan_data.get(Link.IFLA_VXLAN_LOCAL)),
                            "vxlan_port": vxlan_data.get(Link.IFLA_VXLAN_PORT),
                        })
                        if not port.get("offloaded") and self.tc.tunnel_port_init(ifname):
                            port.update({ "offloaded": True })
                        if port.get("offloaded"):
                            log.info("VXLAN port %s (regular) is added as tc-offloaded" % ifname)
                else:
                    log.info("Port %s (regular) is added" % ifname)
        else:
            return
        self.ports[ifname] = port
        self.update_l3vni_mapping(port)

    def rx_rtm_dellink(self, msg):
        ifname = msg.get_attribute_value(msg.IFLA_IFNAME)
        port = self.ports.get(ifname)
        if port:
            if port.get("offloaded") == True:
                if port["kind"] == "eth":
                    self.tc.port_fini(port["ifname"])
                    self.tc_port_vlans_del(port)
                elif port["kind"] == "vxlan":
                    self.tc.tunnel_port_fini(port["ifname"])
                elif port["kind"] == "vlan":
                    self.tc_vlan_vrf_del(port["vlan_id"])
                    log.info("VLAN %d removed from VRF table" % port["vlan_id"])
                log.info("Port %s clear offloads" % port["ifname"])
            log.info("Port %s is removed" % ifname)
            self.ports.pop(ifname)


    def rx_rtm_newneigh(self, msg):
        ifname = self.ifname_by_index.get(msg.ifindex)
        if msg.family == AF_BRIDGE: 
            dst_mac = mac_format(msg.get_attribute_value(msg.NDA_LLADDR))
            vlan = msg.get_attribute_value(msg.NDA_VLAN)
            port = self.ports.get(ifname)
            if not port:
                return
            
            old_entry = dict(self.fdb.get(dst_mac, {}))
            entry = self.fdb.get(dst_mac, {})
            entry.update({
                "type": "unknown",
                "ifname": ifname,
                "dst_mac": dst_mac
            })
            if vlan:
                entry.update({ "vlan": vlan })
            if port["kind"] == "eth":
                if not port["vlans"].get(vlan):
                    # mac must belong to one of port vlan
                    return
                entry.update({
                        "type": "local"
                    })
                # remove existing entry if was changed
                if old_entry and old_entry.get("type", "unknown") != "unknown":
                    if (entry.get("type") == old_entry.get("type") and
                            entry.get("ifname") == old_entry.get("ifname") and
                            entry.get("vlan") == old_entry.get("vlan")):
                        print("FDB Unhanged:", entry, old_entry)
                        return
                    else:
                        print("FDB Changed:", entry, old_entry)
                        self.tc_fdb_del(old_entry)
            elif port["kind"] == "vxlan":
                vxlan_id = port.get("vxlan_id")
                vxlan_port = port.get("vxlan_port")
                vxlan_local_ip = port.get("vxlan_local_ip")
                if not (vxlan_id and vxlan_port and vxlan_local_ip):
                    log.warning("Invalid vxlan parameters for port: %s" % ifname)
                    return  
                vxlan_remote_ip = msg.get_attribute_value(msg.NDA_DST)
                entry.update({
                        "type": "unknown"
                    })
                if vxlan_remote_ip:
                    entry.update({
                        "type": "vxlan",
                        "vxlan_id": vxlan_id,
                        "vxlan_port": vxlan_port,
                        "vxlan_local_ip": vxlan_local_ip,
                        "vxlan_remote_ip": str(vxlan_remote_ip)
                    })
                # remove existing entry if was changed
                if old_entry and old_entry.get("type", "unknown") != "unknown":
                    if (entry.get("type") == old_entry.get("type") and
                            entry.get("ifname") == old_entry.get("ifname") and
                            entry.get("vxlan_id") == old_entry.get("vxlan_id") and
                            entry.get("vxlan_remote_ip") == old_entry.get("vxlan_remote_ip")):
                        print("FDB VXLAN Unchanged:", entry, old_entry)
                        return
                    else:
                        print("FDB VXLAN Changed:", entry, old_entry)
                        self.tc_fdb_del(old_entry)
            else:
                #log.warning("Unsupported port kind for the mac: %s %s (%s)" % (dst_mac, ifname, port["kind"]))
                return
            self.fdb[dst_mac] = entry
            idx = self.fdb.keys().index(dst_mac)+1
            entry["idx"] = idx
            print("MAC ADD:", entry)
            self.tc_fdb_add(entry)
        elif msg.family in (AF_INET, AF_INET6):
            version = msg.get_attribute_value(Neighbor.NDA_DST).version
            dst_ip = str(msg.get_attribute_value(Neighbor.NDA_DST))
            # process only valid dynamic neighbor entries
            if not msg.state in (Neighbor.NUD_REACHABLE, Neighbor.NUD_STALE, Neighbor.NUD_NOARP):
                return
            dst_mac = msg.get_attribute_value(Neighbor.NDA_LLADDR)
            if not dst_mac:
                return
            dst_mac = mac_format(dst_mac)
            port = self.ports.get(ifname)
            # process only neighborts on regular VLAN interfaces
            if not (port and port.get("offloaded") and port["kind"] == "vlan"):
                print("Neighbor port is not supported:", dst_ip, dst_mac, ifname, msg.get_states_string(msg.state))
                return
            
            mac = self.fdb.get(dst_mac)
            # process only neighborts with valid fdb entries
            if not mac:
                print("Neighbor MAC is not offloaded:", dst_ip, dst_mac, ifname, msg.get_states_string(msg.state))
                return
            
            old_entry = dict(port["neighbors"].get(dst_ip, {}))
            entry = port["neighbors"].get(dst_ip, {
                "type": "vlan",
                "version": version,
                "dst_ip": dst_ip,
                "dst_mac": dst_mac,
                "ifname": ifname,
                "src_mac": port["mac"],
                "vrf_table": port["vrf_table"],
                "fdb_ifname": mac["ifname"]
            })

            if mac["type"] == "vxlan":
                entry["type"] = "vxlan"

            # remove existing entry if was changed
            if old_entry:
                if (entry.get("type") == old_entry.get("type") and
                        entry.get("ifname") == old_entry.get("ifname") and
                        entry.get("mac") == old_entry.get("mac") and
                        entry.get("vrf_table") == old_entry.get("vrf_table")):
                    print("NEIGH Unchanged:", entry, old_entry)
                    return
                else:
                    fdb_mac = old_entry.get("mac","")
                    if fdb_mac in self.fdb:
                        self.fdb[fdb_mac]["neigh"] = None
                    print("NEIGH Changed:", entry, old_entry)
                    self.tc_neigh_del(old_entry)

            # update fdb entry with its neighbor IP as well
            mac["neigh"] = dst_ip

            port["neighbors"][dst_ip] = entry
            idx = port["neighbors"].keys().index(dst_ip)+1
            entry["idx"] = idx
            self.tc_neigh_add(entry)


    def rx_rtm_delneigh(self, msg):
        ifname = self.ifname_by_index.get(msg.ifindex,"")
        if msg.family == AF_BRIDGE: 
            dst_mac = mac_format(mac_format(msg.get_attribute_value(msg.NDA_LLADDR)))
            entry = self.fdb.pop(dst_mac, None)
            if entry:
                port = self.ports.get(entry.get("ifname"),"")
                if port:
                    neigh = port["neighbors"].pop(entry.get("neigh", ""), None)
                    if neigh:
                        family = self.get_neigh_family(neigh)
                        ifindex = get_ifindex(neigh.get("ifname",""))
                        self.tc_neigh_del(neigh)
                        if family and ifindex:
                            print(family, ifindex, neigh["dst_ip"])
                            self.neighbor_get(family, ifindex, IPAddress(neigh["dst_ip"]))
                self.tc_fdb_del(entry)
        elif msg.family in (AF_INET, AF_INET6):
            port = self.ports.get(ifname)
            if not port:
                return
            dst_ip = str(msg.get_attribute_value(Neighbor.NDA_DST))
            entry = port["neighbors"].pop(dst_ip, None)
            if entry:
                # clear FDB neighbor reference for its MAC as well
                mac = self.fdb.get(entry.get("mac", ""))
                if mac:
                    mac["neigh"] = None
                self.tc_neigh_del(entry)

    def rx_rtm_newroute(self, msg):
        dst_ip = str(msg.get_attribute_value(msg.RTA_DST, ""))
        gw = str(msg.get_attribute_value(msg.RTA_GATEWAY, ""))
        out_ifname = self.ifname_by_index.get(msg.get_attribute_value(msg.RTA_OIF, ""))
        vrf_table = msg.get_attribute_value(msg.RTA_TABLE)
        if not (gw and out_ifname and vrf_table):
            return
        port = self.ports.get(out_ifname)
        if not port:
            return
        gw_neigh = port["neighbors"].get(gw)
        if not (gw_neigh and gw_neigh["type"] == "vxlan"):
            print("ROUTE port is not supported", dst_ip, gw, out_ifname, vrf_table, gw_neigh)
            return
        version = gw_neigh.get("version")
        src_mac = gw_neigh.get("src_mac")
        dst_mac = gw_neigh.get("dst_mac")
        fdb_ifname = gw_neigh.get("fdb_ifname")
        l3vni_port = self.ports.get(fdb_ifname)
        if not (src_mac and dst_mac and fdb_ifname and l3vni_port and l3vni_port["kind"] == "vxlan" and l3vni_port["vrf_table"] == vrf_table):
            print("ROUTE port is not offloaded", dst_ip, gw, out_ifname, vrf_table, gw_neigh, l3vni_port)
            return
        old_entry = dict(self.routes.get(dst_ip, {}))
        entry = self.routes.get(dst_ip, {
                "type": "vxlan",
                "version": version,
                "ifname": fdb_ifname,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "vrf_table": vrf_table,
                "vxlan_id": l3vni_port["vxlan_id"],
                "vxlan_remote_ip": gw,
                "vxlan_local_ip": l3vni_port["vxlan_local_ip"],
                "vxlan_port": l3vni_port["vxlan_port"]
            })
        # remove existing entry if was changed
        if old_entry:
            if (entry.get("type") == old_entry.get("type") and
                    entry.get("ifname") == old_entry.get("ifname") and
                    entry.get("dst_mac") == old_entry.get("dst_mac") and
                    entry.get("vrf_table") == old_entry.get("vrf_table")):
                print("ROUTE Unchanged:", entry, old_entry)
                return
            else:
                print("NEIGH Changed:", entry, old_entry)
                self.tc_route_del(old_entry)
        self.routes[dst_ip] = entry
        idx = self.routes.keys().index(dst_ip)+1
        entry["idx"] = idx
        self.tc_route_add(entry)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)7s: %(message)s')
    log = logging.getLogger()

    if os.geteuid() != 0:
        sys.exit('This script must be run as root!')

    # groups controls what types of messages we are interested in hearing
    groups = RTMGRP_LINK | RTMGRP_NEIGH | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_IFADDR | RTMGRP_IPV6_ROUTE
    nlmanager = Voyager(groups)

    signal.signal(signal.SIGTERM, nlmanager.signal_term_handler)
    signal.signal(signal.SIGINT, nlmanager.signal_int_handler)

    try:
        nlmanager.listener.supported_messages_add(NLMSG_DONE)
        #nlmanager.filter_by_address_family(True, 'whitelist', RTM_NEWNEIGH, AF_BRIDGE)

        nlmanager.workq.put(('GET_ALL_BR_LINKS', None))
        nlmanager.workq.put(('GET_ALL_LINKS', None))
        nlmanager.workq.put(('GET_ALL_ADDRESSES', None))
        nlmanager.workq.put(('GET_ALL_FDB_NEIGHBORS', None))
        nlmanager.workq.put(('GET_ALL_NEIGHBORS', None))
        nlmanager.workq.put(('GET_ALL_ROUTES', None))

        nlmanager.debug_link(True)
        nlmanager.debug_neighbor(True)
        nlmanager.debug_address(True)
        nlmanager.debug_route(True)

        # NOTE: this will block
        nlmanager.main()
        sys.exit(0)

    except Exception as e:
        log.exception(e)
        nlmanager.shutdown_event.set()
        nlmanager.alarm.set()
        sys.exit(1)
