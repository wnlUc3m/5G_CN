from UeContext import UeContext
from authentication.Hss import Hss
from S1apCommon import ErabContext, NasEMMType, ErabState
from pycrate_mobile.NAS import *
from pycrate_asn1rt.utils import *

from NasPduBuilder import *
from Security import SecurityAlgorithm as SecAlg
from Security import AlgorithmDistinguisher as AlgDist
from Security import SecurityDirection as SecDir

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

class NasHandler:

    MAX_ERABS_PER_UE = 16

    def __init__(self):
        self.hss = Hss()

        # Type of EPS Mobile Identity to handler
        self.eps_mobile_id_type = {}
        self.eps_mobile_id_type[1] = "attach_request_msg_imsi_type_handler"
        self.eps_mobile_id_type[3] = "attach_request_msg_imei_type_handler"
        self.eps_mobile_id_type[6] = "attach_request_msg_guti_type_handler"

    def get_handler(self, nas_eps_mobile_management_msg_type):
        return self.handler_name[nas_eps_mobile_management_msg_type]

    def get_eps_mobile_id_handler(self, eps_mobile_id_type):
        return self.eps_mobile_id_type[eps_mobile_id_type]

    def attach_request_msg_handler(self, nas_pdu, enb_ue_s1ap_id, mme_ue_s1ap_id):
        print "    [-] Attach Request"

        # IMSI, IMEI or GUTY type 
	# TODO: common way of getting this value
	# guti:
        #   * type_of_identity = nas_pdu['EMMAttachRequest']['EPSID']['EPSID'][2].get_val()
        type_of_identity = nas_pdu['EPSID']['EPSID'][2].get_val()

        try:
            method = getattr(self, str(self.get_eps_mobile_id_handler(type_of_identity)))
            return method(nas_pdu, enb_ue_s1ap_id, mme_ue_s1ap_id)
        except KeyError:
            print "EPS Mobile Identity type not supported. Allowed types IMSI, IMEI, GUTY"
            # TODO: retornar un mensaje de error

    def attach_request_msg_imsi_type_handler(self, nas_pdu, enb_ue_s1ap_id, mme_ue_s1ap_id):
        print "    [INFO] IMSI type handler"

        ue_context = UeContext(self.MAX_ERABS_PER_UE) 
        # Set eNB UE S1AP identifier
        ue_context.set_enb_ue_s1ap_id(enb_ue_s1ap_id)
        ue_context.set_mme_ue_s1ap_id(mme_ue_s1ap_id)
        
        # Store UE network capability bitmap
        if nas_pdu['UENetCap']:
            ue_context.store_ue_net_capabilities(nas_pdu['UENetCap'][1].get_val())

        ue_context.set_procedure_transaction_identity(nas_pdu['ESMContainer'][1].get_val()[2])
        #TODO: store ESM info transfer if needed -- mirar en el paquete si es necesario mandar esa info

        # Init NAS count
        ue_context.eps_security_ctx.set_dl_nas_count(0)
        ue_context.eps_security_ctx.set_ul_nas_count(0)

        # Add eNB information to UE context
        # TODO: Es una informacion que devuelve el socket (struct sctp_sndrcvinfo)

        # Init EPS Radio Access Bearers (E-RABS) - by default state = DEACTIVATED
        for i in range(0, NasHandler.MAX_ERABS_PER_UE):
            ue_context.erabs[i] = ErabContext(i)

        # Store IMSI
        ue_context.set_imsi(nas_pdu['EPSID'][1].decode()[1])

        # Get authentication vectors from HSS
        #   - Return: k_asme, autn, rand, xres
        RAND, XRES, AUTN, K_ASME = self.hss.generate_authentication_information_answer(ue_context.get_imsi())

        # Store security information in context
        ue_context.eps_security_ctx.set_rand(RAND)
        ue_context.eps_security_ctx.set_xres(XRES)
        ue_context.eps_security_ctx.set_autn(AUTN)
        ue_context.eps_security_ctx.set_k_asme(K_ASME)
        self.current_xres = hexlify(XRES)
        self.current_ue_context = ue_context

        nas_pdu_reply = build_authentication_request_pdu(RAND, AUTN)

        return nas_pdu_reply
        
    def attach_request_msg_imei_type_handler(nas_pdu, enb_ue_s1ap_id):
        # TODO: not implemented
        print "    [ERROR] Attach Request with imei not implemented"

    def attach_request_msg_guty_type_handler(nas_pdu, enb_ue_s1ap_id):
        # TODO: not implemented
        print "    [ERROR] Attach Request with guty not implemented"

    def authentication_response_msg_handler(self, nas_pdu):
        print "    [-] Authentication Response"

        received_authentication_response_parameter = hexlify(nas_pdu['RES'][1].get_val())
        valid_response = True
        for i in range(0,16):
            if str(received_authentication_response_parameter)[i] != str(self.current_xres)[i]:
                print "    [WARNING] RES mismatch - recv: %s expected: %s" % (received_authentication_response_parameter[i], self.current_xres[i])
                valid_response = False
                break

        print "    [INFO] UE authentication: %s" % (valid_response)
        if valid_response:
            # Integrity protection
            k_asme = self.current_ue_context.eps_security_ctx.get_k_asme()

            # Generate NAS security keys k_nas_enc and k_nas_int
            k_nas_int, k_nas_enc  = self.hss.generate_k_nas(k_asme, SecAlg.EIA2_128, AlgDist.NAS_INT, SecAlg.EEA0, AlgDist.NAS_ENC)
            self.current_ue_context.eps_security_ctx.set_k_nas_enc(k_nas_enc)
            self.current_ue_context.eps_security_ctx.set_k_nas_int(k_nas_int)

            # Generate k_enb with k_asme and ul_nas_count
            k_enb = self.hss.generate_k_enb(k_asme, self.current_ue_context.eps_security_ctx.get_ul_nas_count())
            self.current_ue_context.eps_security_ctx.set_k_enb(k_enb)

            # SecurityModeCommand message creation (with integrity protection)
            integrity_protected_nas_pdu_reply = build_security_mode_command_pdu(k_nas_int, SecDir.DOWNLINK, SecAlg.EEA0, SecAlg.EIA2_128, self.current_ue_context.get_caps())
            #integrity_protected_nas_pdu_reply = build_security_mode_command_pdu(k_nas_int, SecDir.DOWNLINK, SecAlg.EEA0, SecAlg.EIA1_128, self.current_ue_context.get_caps())

        else:
            # TODO: return concrete error
            print "    [WARNING] RES mismatch NOT IMPLEMENTED NAS_HANDLER"
            integrity_protected_nas_pdu_reply = ""
                                  
        return integrity_protected_nas_pdu_reply, NasEMMType.MSG_SECURITY_MODE_COMMAND

    def security_mode_complete_msg_handler(self, nas_pdu, assigned_ip):
        print "    [-] Security Mode Complete"

        # TODO: Handle IMEI-SV
        if nas_pdu['IMEISV']:
            print "    [WARNING] IMEI-SV not handled"

        # In legacy implementations
        #   Create session request
        #   Handle create session response
        
        k_nas_int = self.current_ue_context.eps_security_ctx.get_k_nas_int()
        k_nas_enc = self.current_ue_context.eps_security_ctx.get_k_nas_enc()
        # TODO: Get PLMN from S1apHandler
        plmn = chr(int("00000010",2)) + chr(int("11111000",2)) + chr(int("00111001",2))
        nas_pdu_reply = build_attach_accept_pdu(plmn, SecDir.DOWNLINK, k_nas_int, SecAlg.EIA2_128, k_nas_enc, SecAlg.EEA0, assigned_ip)

        return nas_pdu_reply,NasEMMType.MSG_ATTACH_ACCEPT 

    def attach_complete_msg_handler(self, nas_pdu):
        print "    [-] Attach Complete"

        # TODO: Setup GTPtunnel in the GW

        return "", NasEMMType.MSG_ATTACH_COMPLETE
        

    def handle_nas_pdu(self, nas_pdu, *params):
        security_header_type, proto_discriminator = nas_pdu[0][0].get_val(), nas_pdu[0][1].get_val()
        
        # Integrity-protected and ciphered NAS message = 2 (srsLTE)
        # Integrity-protected and ciphered NAS message with new EPS Secirity Context = 4 (OAI)
        if security_header_type == 2 or security_header_type == 4:
            
            # TODO: Check integrity (mac of the message) pycrate_corenet/HdlrUES1.py
            # process_nas_sec_mac()

            # if EEA0 takes protected nas_pdu
            buf = nas_pdu[3].get_val()
            
            # else
            # nas_pdu.decrypt(self.current_ue_context.eps_security_ctx.get_k_nas_enc(), 0, 0, 0)
            # buf = nas_pdu._dec_msg

            nas_pdu, err = parse_NASLTE_MO(buf, inner=False)

	# TODO: common way of getting msg type for both imsi and guti messages
        #  - guti:
        #       * nas_eps_mobility_management_msg_type = nas_pdu[3][0][2].get_val()
        
        # Message type
        nas_eps_mobility_management_msg_type = nas_pdu['EMMHeader'][2].get_val()
        print "    [INFO] NAS_EPS_MobilityManagementMessageType %s" % nas_eps_mobility_management_msg_type

        # Attach Request
        if nas_eps_mobility_management_msg_type == NasEMMType.MSG_ATTACH_REQUEST:
            enb_ue_s1ap_id = params[0]
            mme_ue_s1ap_id = params[1]
            return self.attach_request_msg_handler(nas_pdu, enb_ue_s1ap_id, mme_ue_s1ap_id)

        # Authentication Response        
        elif nas_eps_mobility_management_msg_type == NasEMMType.MSG_AUTH_RESPONSE:
            return self.authentication_response_msg_handler(nas_pdu)
        
        # Security Mode Complete 
        elif nas_eps_mobility_management_msg_type == NasEMMType.MSG_SECURITY_MODE_COMPLETE:
            # IP assigned to the UE
            assigned_ip = params[0]
            return self.security_mode_complete_msg_handler(nas_pdu, assigned_ip)

        # Attach Complete
        elif nas_eps_mobility_management_msg_type == NasEMMType.MSG_ATTACH_COMPLETE:
            return self.attach_complete_msg_handler(nas_pdu)

        elif nas_eps_mobility_management_msg_type == NasEMMType.MSG_AUTHENTICATION_FAILURE:
            print "    [ERROR] NAS_EPS_MobilityManagement Authentication Failure not yet implemented"

        else:
            print "    [ERROR] NAS_EPS_MobilityManagementMessageType %s not handled" % nas_eps_mobility_management_msg_type
 

    '''
        Context Management functions
    '''
    def get_imsi_current_ue(self):
        return self.current_ue_context.get_imsi()
    def get_mme_ue_s1ap_id_current_ue(self):
        return self.current_ue_context.get_mme_ue_s1ap_id()
    def get_enb_ue_s1ap_id_current_ue(self):
        return self.current_ue_context.get_enb_ue_s1ap_id()
    def get_k_enb_current_ue(self):
        return self.current_ue_context.eps_security_ctx.get_k_enb()
    
    def request_erab(self, erab_id, gw_teid):
        self.current_ue_context.request_erab(erab_id, gw_teid)

    def setup_erab(self, enb_gtp_ip, enb_fteid):
        for erab in self.current_ue_context.erabs.keys():
            if self.current_ue_context.erabs[erab].get_state() == ErabState.ERAB_CTX_REQUESTED:
                self.current_ue_context.set_enb_gtp_ip_addr(enb_gtp_ip)
                self.current_ue_context.erabs[erab].set_enb_fteid(enb_fteid)
                print "      [INFO]  E-RAB %s configured. eNB:%s-%s" % (erab, enb_gtp_ip, enb_fteid)
                
