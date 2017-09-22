from xmlsig import SignatureContext


class XAdESContext(SignatureContext):
    def sign(self, node):
        return super(XAdESContext, self).sign(node)

    def verify(self, node):
        return super(XAdESContext, self).sign(node)