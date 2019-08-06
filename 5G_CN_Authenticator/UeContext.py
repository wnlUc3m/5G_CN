from S1apCommon import EpsSecurityContext, EpsMobilityManagementCtx, EpsConnectionManagementCtx, ErabContext, ErabState

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

class UeContext:

    UE_CAPABILITIES = ["EEA0","128-EEA1","128-EEA2","128-EEA3","EEA4","EEA5","EEA6","EEA7","EIA0","128-EIA1","128-EIA2","128-EIA3","EIA4","EIA5","EIA6","EIA7"]
    MS_CAPABILITIES = []

    def __init__(self, max_erabs_per_ue):
        self.imsi = ""
        self.erabs = {}

        self.emm_context = EpsMobilityManagementCtx()
        self.ecm_context = EpsConnectionManagementCtx()
        self.eps_security_ctx = EpsSecurityContext()

    def get_imsi(self):
        return self.imsi
    def get_enb_ue_s1ap_id(self):
        return self.ecm_context.get_enb_ue_s1ap_id()
    def get_mme_ue_s1ap_id(self):
        return self.ecm_context.get_mme_ue_s1ap_id()
    def get_caps(self):
        return self.eps_security_ctx.get_ue_net_caps()
    def getenb_gtp_ip_addr(self):
        return self.enb_gtp_ip_addr

    def set_enb_ue_s1ap_id(self, value):
        self.ecm_context.set_enb_ue_s1ap_id(value)
    def set_mme_ue_s1ap_id(self, value):
        self.ecm_context.set_mme_ue_s1ap_id(value)
    def set_procedure_transaction_identity(self, value):
        self.emm_context.set_procedure_transaction_id(value)
    def set_imsi(self, imsi):
        self.imsi = imsi
    def set_enb_gtp_ip_addr(self, value):
        self.enb_gtp_ip_addr = value
    def store_ue_net_capabilities(self, net_capabilities):
        self.eps_security_ctx.store_ue_net_capabilities(net_capabilities)

    '''
        This method updates the status of a specific E-RAB to requested right after sending initialContextSetupRequest message
        input:
            - E-RAB id to set up
            - TEID assigned to the GW
    '''
    def request_erab(self, erab_id, gw_teid):
        self.erabs[erab_id] = ErabContext(erab_id)
        self.erabs[erab_id].set_state(ErabState.ERAB_CTX_REQUESTED)
        self.erabs[erab_id].set_gw_fteid(gw_teid)
	



