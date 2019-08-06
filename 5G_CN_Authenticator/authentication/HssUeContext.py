class HssUeContext:

    def __init__(self, name, imsi, key, op, amf, sqn):
        self.name = name
        self.imsi = imsi
        self.key = key
        self.op = op
        self.amf = amf
        self.sqn = sqn

    # Pre Shared Keys
    def get_name(self):
        return self.name
    def get_imsi(self):
        return self.imsi
    def get_key(self):
        return self.key
    def get_op(self):
        return self.op
    def get_amf(self):
        return self.amf
    # Generated Keys
    def get_sqn(self):
        return self.sqn
    def get_rand(self):
        return self.rand
    def set_sqn(self, sqn):
        self.sqn = sqn
    def set_rand(self, rand):
        self.rand = rand
    # Derived Authentication vectors
    def get_ik(self):
        return self.ik
    def get_ck(self):
        return self.ck
    def get_ak(self):
        return self.ak
    def get_xres(self):
        return self.xres
    def get_mac(self):
        return self.mac
    def get_autn(self):
        return self.autn
    def set_ik(self, ik):
        self.ik = ik
    def set_ck(self, ck):
        self.ck = ck
    def set_ak(self, ak):
        self.ak = ak
    def set_xres(self, xres):
        self.xres = xres
    def set_mac(self, mac):
        self.mac = mac
    def set_autn(self, autn):
        self.autn = autn
