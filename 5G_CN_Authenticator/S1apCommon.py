
'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

class EpsMobilityManagementCtx:

    def get_procedure_transaction_id(self):
        return self.procedure_transaction_id
    def get_attach_type(self):
        return self.attach_type
    def get_ue_ip(self):
        return self.ue_ip

    def set_procedure_transaction_id(self, t_id):
        self.procedure_transaction_id = t_id
    def set_attach_type(self, attach_type):
        self.attach_type = attach_type
    def set_ue_ip(self, ip):
        self.ue_ip = ip       

class EpsConnectionManagementCtx:

    # TODO: Store connection socket with the eNB
    def get_enb_ue_s1ap_id(self):
        return self.enb_ue_s1ap_id
    def get_mme_ue_s1ap_id(self):
        return self.mme_ue_s1ap_id        

    def set_enb_ue_s1ap_id(self, value):
        self.enb_ue_s1ap_id = value
    def set_mme_ue_s1ap_id(self, value):
        self.mme_ue_s1ap_id = value

class EpsSecurityContext:

    UE_CAPABILITIES = ["EEA0","128-EEA1","128-EEA2","128-EEA3","EEA4","EEA5","EEA6","EEA7","EIA0","128-EIA1","128-EIA2","128-EIA3","EIA4","EIA5","EIA6","EIA7"]

    def __init__(self):
        self.dl_nas_count = 0
        self.ul_nas_count = 0
        self.ciphering_alg = ""
        self.integrity_alg = ""
        self.k_nas_enc = [0] * 32
        self.k_nas_int = [0] * 32

        self.ue_net_capabilities = {}
        for cap in self.UE_CAPABILITIES:
            self.ue_net_capabilities[cap] = 0

        '''
        self.ms_network_cap_present = False
        self.ms_net_capabilities = {}
        for cap in UeContext.MS_CAPABILITIES:
            self.ms_net_capabilities[cap] = 0
        '''

    def set_k_asme(self, value):
        self.k_asme = value
    def set_xres(self, value):
        self.xres = value
    def set_dl_nas_count(self, value):
        self.dl_nas_count = value                
    def set_ul_nas_count(self, value):
        self.ul_nas_count = value
    def set_ciphering_alg(self, value):
        self.ciphering_alg = value
    def set_integrity_alg(self, value):
        self.integrity_alg = value
    def set_k_nas_enc(self, value):
        self.k_nas_enc = value
    def set_k_nas_int(self, value):
        self.k_nas_int = value
    def set_k_enb(self, value):
        self.k_enb = value
    def set_rand(self, value):
        self.rand = value
    def set_autn(self, value):
        self.autn = value

    def get_k_nas_enc(self):
        return self.k_nas_enc
    def get_k_nas_int(self):
        return self.k_nas_int
    def get_k_asme(self):
        return self.k_asme
    def get_dl_nas_count(self):
        return self.dl_nas_count
    def get_ul_nas_count(self):
        return self.ul_nas_count
    def get_k_enb(self):
        return self.k_enb
    def get_ue_net_caps(self):
        return self.ue_net_capabilities

    def store_ue_net_capabilities(self, net_capabilities):
        for i,cap in enumerate(self.UE_CAPABILITIES):
            if net_capabilities[i] == 1:
                self.ue_net_capabilities[cap] = 1
            else:
                self.ue_net_capabilities[cap] = 0

class ErabState:
    ERAB_DEACTIVATED = 0
    ERAB_CTX_REQUESTED = 1
    ERAB_CTX_SETUP = 2
    ERAB_ACTIVE = 4

class ErabContext:
    def __init__(self, identifier):
        self.state = ErabState.ERAB_DEACTIVATED
        self.erab_id = identifier
        self.enb_fteid = -1
        self.gw_fteid = -1
    def get_state(self):
        return self.state
    def get_gw_fteid(self):
        return self.gw_fteid
    def get_enb_fteid(self):
        return self.enb_fteid
    def get_enb_ip(self):
        return self.enb_gtp_ip

    def set_state(self, value):
        if value not in [0, 1, 2, 4]:
            print "     [ERROR] Erab State not supported"
        self.state = value
    def set_gw_fteid(self, value):
        self.gw_fteid = value
    def set_enb_fteid(self, value):
        self.enb_fteid = value        
    def set_enb_gtp_ip_addr(self, value):
        self.enb_gtp_ip = value

class NasEMMType:

    MSG_ATTACH_REQUEST = 65
    MSG_ATTACH_ACCEPT = 66
    MSG_ATTACH_COMPLETE = 67

    MSG_AUTH_REQUEST = 82
    MSG_AUTH_RESPONSE = 83

    MSG_AUTHENTICATION_FAILURE = 92    
    MSG_SECURITY_MODE_COMMAND = 93
    MSG_SECURITY_MODE_COMPLETE = 94

class S1apPDUType:
    MSG_INITIATING = "initiatingMessage"
    MSG_SUCCESSFULOUTCOME = "successfulOutcome"
