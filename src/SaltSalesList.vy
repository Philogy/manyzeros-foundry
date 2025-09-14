#pragma version >=0.4.3
#pragma optimize gas

import ISubZero

struct State:
    owner: address
    next10: uint16
    next12: uint16
    next14: uint16
    price10: uint256
    price12: uint256
    price14: uint256

UnauthorizedError: constant(Bytes[4]) = method_id("Unauthorized()")
PriceAboveMaxError: constant(Bytes[4]) = method_id("PriceAboveMax()")
UnsupportedZerosError: constant(Bytes[4]) = method_id("UnsupportedZeros()")
WrongValueError: constant(Bytes[4]) = method_id("WrongValue()")
MaxSearchIterationsError: constant(Bytes[4]) = method_id("MaxSearchIterations()")
SaltsSoldOutError: constant(Bytes[4]) = method_id("SaltsSoldOut()")
MissingDesiredZerosError: constant(Bytes[4]) = method_id("MissingDesiredZeros()")

PRICE_SCALE: constant(uint256) = 10**14
MAX_PRICE: constant(uint256) = (2**16 - 1)

MAX_SEARCH_ITERATIONS: constant(uint256) = 20

SALT_LIST_PADDING_BYTES: constant(uint256) = 1
SALT_ENTRY_BYTES: constant(uint256) = 13
SALT_ENTRY_NONCE_OFFSET: constant(uint256) = 0
SALT_ENTRY_SALT_OFFSET: constant(uint256) = 1
COMPACT_SALTS_LIST: public(immutable(address))
SALT_OWNER: public(immutable(address))

# Stores: `owner: address, next10: uint16, next12: uint16, next14: uint16, price10: uint16, price12: uint16, price14: uint16`
_packed_state: uint256

@deploy
def __init__(salt_owner: address, salts_list: address, initial_state: State):
    COMPACT_SALTS_LIST = salts_list
    SALT_OWNER = salt_owner
    self._set_state(initial_state)

@external
def transfer_ownership(new_owner: address):
    self._check_owner()
    state: State = self._get_state()
    state.owner = new_owner
    self._set_state(state)

@external
def set_prices(price10: uint256, price12: uint256, price14: uint256):
    self._check_owner()
    state: State = self._get_state()
    state.price10 = price10
    state.price12 = price12
    state.price14 = price14
    self._set_state(state)
    
@payable
@external
def buy_salt(zeros: uint8) -> uint256:
    state: State = self._get_state()
    price: uint256 = 0
    current_index: uint16 = 0
    end_index: uint16 = 0
    price, current_index, end_index = self._get_zeros_params(state, zeros)
    cost: uint256 = unsafe_mul(price, PRICE_SCALE)
    self.require(msg.value == cost, WrongValueError)
    raw_call(state.owner, b"", value=cost)

    nonce: uint8 = 0
    salt: uint256 = 0
    for _: uint256 in range(MAX_SEARCH_ITERATIONS):
        self.require(current_index < end_index, SaltsSoldOutError)
        nonce, salt = self._get_list_entry(current_index)
        current_index = unsafe_add(current_index, 1)
        already_minted: bool = (staticcall ISubZero.SUB_ZERO.getTokenData(salt))[0]
        if not already_minted:
            self.require(self._check_zeros(zeros, nonce, salt), MissingDesiredZerosError)
            extcall ISubZero.SUB_ZERO.mint(msg.sender, salt, nonce)
            if zeros == 10:
                state.next10 = current_index
            elif zeros == 12:
                state.next12 = current_index
            elif zeros == 14:
                state.next14 = current_index
            self._set_state(state)
            return salt
    raw_revert(MaxSearchIterationsError)

@external
def update_index(zeros: uint8, iterations: uint256):
    state: State = self._get_state()
    current_index: uint16 = 0
    end_index: uint16 = 0
    price: uint256 = 0
    price, current_index, end_index = self._get_zeros_params(state, zeros)
    for _: uint256 in range(iterations, bound=MAX_SEARCH_ITERATIONS):
        if current_index == end_index:
            break
        salt: uint256 = self._get_list_entry(current_index)[1]
        already_minted: bool = (staticcall ISubZero.SUB_ZERO.getTokenData(salt))[0]
        if not already_minted:
            break
        current_index = unsafe_add(current_index, 1)
    if zeros == 10:
        state.next10 = current_index
    elif zeros == 12:
        state.next12 = current_index
    elif zeros == 14:
        state.next14 = current_index
    self._set_state(state)


@external
@view
def get_owner() -> address:
    return self._get_owner()    

@external
@view
def get_prices() -> (uint256, uint256, uint256):
    state: State = self._get_state()
    return (state.price10, state.price12, state.price14)

@view
def _get_list_entry(index: uint16) -> (uint8, uint256):
    entry_bytes: Bytes[SALT_ENTRY_BYTES] = slice(
        COMPACT_SALTS_LIST.code,
        unsafe_add(SALT_LIST_PADDING_BYTES, unsafe_mul(convert(index, uint256), SALT_ENTRY_BYTES)),
        SALT_ENTRY_BYTES,
    )
    nonce: uint8 = convert(slice(entry_bytes, SALT_ENTRY_NONCE_OFFSET, 1), uint8)
    base_salt: uint96 = convert(slice(entry_bytes, SALT_ENTRY_SALT_OFFSET, 12), uint96)
    salt: uint256 = (convert(SALT_OWNER, uint256) << 96) | convert(base_salt, uint256)
    return (nonce, salt)

@view
def _total_salts() -> uint256:
    return (COMPACT_SALTS_LIST.codesize) // SALT_ENTRY_BYTES

@view
def _check_owner():
    owner: address = self._get_owner()
    self.require(msg.sender == owner, UnauthorizedError)

@view
def _get_owner() -> address:
    return self._get_state().owner

@view
def _get_zeros_params(state: State, zeros: uint8) -> (uint256, uint16, uint16):
    if zeros == 10:
        return (state.price10, state.next10, state.next12)
    if zeros == 12:
        return (state.price12, state.next12, state.next14)
    if zeros == 14:
        return (state.price14, state.next14, convert(self._total_salts(), uint16))
    raw_revert(UnsupportedZerosError)

@view
def _check_zeros(zeros: uint8, nonce: uint8, salt: uint256) -> bool:
    addr: address = staticcall ISubZero.SUB_ZERO.computeAddress(convert(salt, bytes32), nonce)
    return convert(addr, uint256) >> unsafe_sub(160, unsafe_mul(zeros, 4)) == 0


def _set_state(state: State):
    self.require(state.price10 <= MAX_PRICE, PriceAboveMaxError)
    self.require(state.price12 <= MAX_PRICE, PriceAboveMaxError)
    self.require(state.price14 <= MAX_PRICE, PriceAboveMaxError)
    self._packed_state = convert(state.owner, uint256) << 96\
        | convert(state.next10, uint256) << 80\
        | convert(state.next12, uint256) << 64\
        | convert(state.next14, uint256) << 48\
        | (state.price10) << 32\
        | (state.price12) << 16\
        | (state.price14)

@view
def _get_state() -> State:
    packed_state: uint256 = self._packed_state
    mask: uint256 = convert(0xffff, uint256)
    return State(
        owner = convert(packed_state >> 96, address),
        next10 = convert((packed_state >> 80) & mask, uint16),
        next12 = convert((packed_state >> 64) & mask, uint16),
        next14 = convert((packed_state >> 48) & mask, uint16),
        price10 = (packed_state >> 32) & mask,
        price12 = (packed_state >> 16) & mask,
        price14 = packed_state & mask
    )

@pure
def _trunc16(x: uint256) -> uint16:
    return convert(x & convert(0xffff, uint256), uint16)
        

@pure
def require(condition: bool, error_message: Bytes[4]):
    if not condition:
        raw_revert(error_message)

