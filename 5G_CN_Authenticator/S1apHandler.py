from pycrate_core.utils import uint_to_bytes
from pycrate_mobile.TS24008_IE import PLMN
from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
from binascii import hexlify
import binascii
from socket import inet_ntoa

from pycrate_mobile.NAS import *
from pycrate_mobile.TS24301_IE import *

from NasHandler import NasHandler
from UeContext import UeContext
from S1apPduBuilder import *
from S1apCommon import NasEMMType, S1apPDUType
import requests, json

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

# TODO: Extend to handle multiple UEs
class S1apHandler:

    MME_UE_S1AP_ID = 0
    CNTRL_GW_IP = '192.168.250.20'

    def __init__(self, pool):
        self.handler_name = {}
        self.handler_name['S1SetupRequest'] = "s1setup_request_msg_handler"
        self.handler_name['InitialUEMessage'] = "initial_ue_msg_handler"
        self.handler_name['UplinkNASTransport'] = "uplink_nas_transport_msg_handler"
        self.handler_name['UECapabilityInfoIndication'] = "UE_capability_info_indication_handler"

        self.MME_CAPACITY = 10
        # PLMN creation: 02f839 => MCC=208 MNC=93
        self.MME_PLMN = chr(int("00000010",2)) + chr(int("11111000",2)) + chr(int("00111001",2))

        self.MME_GID = 4
        self.MME_CODE = 1

        self.nas = NasHandler()

        # TODO: dynamic gw assignment
        self.gw_ip = '192.168.20.10'
        self.ip_pool = pool

    def get_handler(self, s1ap_pdu_id):
        return self.handler_name[s1ap_pdu_id]

    def get_next_mme_ue_s1ap_id(self):
        S1apHandler.MME_UE_S1AP_ID += 1
        return S1apHandler.MME_UE_S1AP_ID

    def s1setup_request_msg_handler(self,s1ap_header):
        print "  [-] S1SetupRequest message received"

        return build_s1setup_response(self.MME_PLMN, self.MME_GID, self.MME_CODE, self.MME_CAPACITY), 'REPLY'

    def initial_ue_msg_handler(self, s1ap_pdu):
        print "    [-] InitialUEMessage received"
        
        enb_ue_s1ap_id = get_val_at(s1ap_pdu, ['initiatingMessage','value', 'InitialUEMessage','protocolIEs',0,'value','ENB-UE-S1AP-ID'])
        mme_ue_s1ap_id = self.get_next_mme_ue_s1ap_id()

        # Extract NAS PDU
        nas_pdu_str = get_val_at(s1ap_pdu, ['initiatingMessage','value', 'InitialUEMessage','protocolIEs',1,'value','NAS-PDU'])
        nas_pdu_hex = "".join("{:02x}".format(ord(c)) for c in nas_pdu_str)

        # TODO: err returns an error code that must be handled in order to reply with the corresponding NAS message
        nas_pdu, err = parse_NAS_MO(unhexlify(nas_pdu_hex))
        nas_pdu_to_reply = self.nas.handle_nas_pdu(nas_pdu, enb_ue_s1ap_id, mme_ue_s1ap_id)
        
        return build_downlink_nas_transport(mme_ue_s1ap_id, enb_ue_s1ap_id, nas_pdu_to_reply), 'REPLY'

    def uplink_nas_transport_msg_handler(self, s1ap_pdu):
        print "  [-]   UplinkNASTransport message received -- IMSI: %s" % self.nas.get_imsi_current_ue()

        # Extract NAS PDU
        nas_pdu_str = get_val_at(s1ap_pdu, ['initiatingMessage','value', 'UplinkNASTransport','protocolIEs',2,'value','NAS-PDU'])
        nas_pdu_hex = "".join("{:02x}".format(ord(c)) for c in nas_pdu_str)

        # TODO: search for an IP address to be assigned
        assigned_ip = self.ip_pool[0].keys()[0]

        # TODO: err returns an error code that must be handled in order to reply with the corresponding NAS message 
        nas_pdu, err = parse_NAS_MO(unhexlify(nas_pdu_hex))
        nas_pdu_to_reply, inner_nas_emm_type = self.nas.handle_nas_pdu(nas_pdu, assigned_ip)

        if inner_nas_emm_type == NasEMMType.MSG_SECURITY_MODE_COMMAND:
            return build_downlink_nas_transport( self.nas.get_mme_ue_s1ap_id_current_ue(), 
                                                                self.nas.get_enb_ue_s1ap_id_current_ue(), 
                                                                nas_pdu_to_reply), 'REPLY'

        elif inner_nas_emm_type == NasEMMType.MSG_ATTACH_ACCEPT:
            # Change E-RAB state to Context Setup Requested and save S-GW control F-TEID
            erab_id = 5
            gw_teid = 1
            self.nas.request_erab(erab_id, gw_teid)
            return build_downlink_nas_transport_for_attach_accept(  self.nas.get_mme_ue_s1ap_id_current_ue(), 
                                                                    self.nas.get_enb_ue_s1ap_id_current_ue(), 
                                                                    self.nas.get_k_enb_current_ue(),
                                                                    erab_id,
                                                                    gw_teid,
                                                                    nas_pdu_to_reply,
                                                                    self.gw_ip), 'REPLY'
        elif inner_nas_emm_type == NasEMMType.MSG_ATTACH_COMPLETE:
            return "", 'ACK'

    def E_RAB_setup_handler():
        print "s1ap message received"

    def initial_context_setup_handler():
        print "s1ap message received"

    def initial_UE_msg_handler():
        print "s1ap message received"

    def uplink_nas_transport_handler():
        print "s1ap message received"

    def s1_setup_handler():
        print "s1ap message received"

    def UE_capability_info_indication_handler(self, s1ap_pdu):
        #TODO: store information from this message if needed
        print "  [-]   UECapabilityInfoIndication message received"
        return "", "ACK"

    def handle_s1ap_pdu(self, s1ap_pdu):
        s1ap = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
        s1ap.from_aper(binascii.unhexlify(s1ap_pdu))
        
        if s1ap.get_val()[0] == S1apPDUType.MSG_INITIATING:
            # print "  [-] Initiating Message"

            # Extract the value field of the message and ask for the method that handles it
            s1ap_pdu_msg_value = str(get_val_at(s1ap, ['initiatingMessage', 'value'])).split( "'")[1]

            method = getattr(self, str(self.get_handler(s1ap_pdu_msg_value)))
            return method(s1ap)

        elif s1ap.get_val()[0] == S1apPDUType.MSG_SUCCESSFULOUTCOME:
            # print "  [-] SuccessfulOutcome Message"
            enb_transport_layer_addr = get_val_at(s1ap, ['successfulOutcome','value', 'InitialContextSetupResponse','protocolIEs',2,'value', 'E-RABSetupListCtxtSURes',0 ,'value', 'E-RABSetupItemCtxtSURes', 'transportLayerAddress']) 
            enb_gtp_fteid = get_val_at(s1ap,['successfulOutcome','value', 'InitialContextSetupResponse','protocolIEs',2,'value', 'E-RABSetupListCtxtSURes', 0, 'value', 'E-RABSetupItemCtxtSURes', 'gTP-TEID'])

            enb_gtp_ip = inet_ntoa(uint_to_bytes(*enb_transport_layer_addr))
            enb_gtp_fteid = bytes_to_uint(enb_gtp_fteid, 32)
            # Finish E-RAB configuration
            self.nas.setup_erab(enb_gtp_ip, enb_gtp_fteid)

            # TODO: Configure GTP in Gateway
            self.configure_gtp_gw(self.ip_pool[0].keys()[0], enb_gtp_fteid, self.gw_ip, enb_gtp_ip)            

            # Store information about the connections
            self.store_information(self.ip_pool[0].keys()[0], enb_gtp_fteid, self.gw_ip, enb_gtp_ip)

            return "", 'ACK'

        else:
            print "S1ap message not recognized"
            print show(s1ap)
            #TODO: crear un mensaje de respuesta de error
    
    def configure_gtp_gw(self, ue_ip, fteid, tun_ip_gw, tun_ip_enb):
        url = "http://%s:8080/gtpcontroller/" % S1apHandler.CNTRL_GW_IP
        headers = {'Authorization': 'Bearer ', "Content-Type": "application/json"}
        data = {
                'enb_tun_ip': tun_ip_enb,
                'gw_tun_ip':tun_ip_gw,
                'ue_ip': ue_ip,
                'teid': fteid,
                }
        response = requests.post(url, data=json.dumps(data), headers=headers)

        print response.text     

    def store_information(self, ue_ip, fteid, tun_ip_gw, tun_ip_enb):
        # Store context data
        connections_file = "/home/user/sdn_based_epc/connections.txt"
        with open(connections_file, 'r') as f:
            if not f.read(1):
                f.close()
                f = open(connections_file, 'w')
                f.write("ue_ip fteid tun_ip_gw tun_ip_enb\n")
                f.write("%s %s %s %s\n" % (ue_ip, fteid, tun_ip_gw, tun_ip_enb))
            else:
                f.close()
                f = open(connections_file, 'a')
                print "  [INFO] Information correctly stored"
                # TODO: Update how IPs are stored
                f.write("%s %s %s %s\n" % (ue_ip, fteid, tun_ip_gw, tun_ip_enb))
            f.close()


    
