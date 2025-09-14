interface ISubZero:
    def mint(to: address, id: uint256, nonce: uint8): nonpayable
    def getTokenData(id: uint256) -> (bool, uint8): view
    def computeAddress(salt: bytes32, nonce: uint8) -> address: view
    
SUB_ZERO: constant(ISubZero) = ISubZero(0x000000000000b361194cfe6312EE3210d53C15AA)
