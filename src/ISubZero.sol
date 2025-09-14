// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {SUB_ZERO_INITCODE} from "./sub-zero-code.sol";

ISubZero constant SUB_ZERO = ISubZero(payable(0x000000000000b361194cfe6312EE3210d53C15AA));

/// @author philogy <https://github.com/philogy>
interface ISubZero {
    error AccountBalanceOverflow();
    error AlreadyInitialized();
    error AlreadyMinted();
    error BalanceQueryForZeroAddress();
    error DeploymentFailed();
    error DomainSeparatorsInvalidated();
    error InsufficientValue();
    error InvalidFee();
    error InvalidSignature();
    error NewOwnerIsZeroAddress();
    error NoHandoverRequest();
    error NoRenderer();
    error NonceAlreadyInvalidated();
    error NotAuthorizedBuyer();
    error NotAuthorizedClaimer();
    error NotOwnerNorApproved();
    error PastDeadline();
    error RendererLockedIn();
    error RoyaltyOverflow();
    error RoyaltyReceiverIsZeroAddress();
    error TokenAlreadyExists();
    error TokenDoesNotExist();
    error TransferFromIncorrectOwner();
    error TransferToNonERC721ReceiverImplementer();
    error TransferToZeroAddress();
    error Unauthorized();

    event Approval(address indexed owner, address indexed account, uint256 indexed id);
    event ApprovalForAll(address indexed owner, address indexed operator, bool isApproved);
    event FeeSet(uint16 fee);
    event OwnershipHandoverCanceled(address indexed pendingOwner);
    event OwnershipHandoverRequested(address indexed pendingOwner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
    event RendererSet(address indexed renderer);
    event Transfer(address indexed from, address indexed to, uint256 indexed id);

    fallback() external payable;
    receive() external payable;

    function CROSS_CHAIN_DOMAIN_SEPARATOR() external view returns (bytes32);
    function DEPLOY_PROXY_INITHASH() external view returns (bytes32);
    function FULL_DOMAIN_SEPARATOR() external view returns (bytes32);
    function addressOf(uint256 id) external view returns (address vanity);
    function approve(address account, uint256 id) external payable;
    function balanceOf(address owner) external view returns (uint256 result);
    function calculateBuyCost(uint256 sellerPrice) external view returns (uint256);
    function claimGivenUpWithSig(
        address to,
        uint256 id,
        uint8 nonce,
        address claimer,
        uint256 deadline,
        bytes memory signature
    ) external;
    function computeAddress(bytes32 salt, uint8 nonce) external view returns (address vanity);
    function contractURI() external view returns (string memory);
    function deploy(uint256 id, bytes memory initcode) external payable returns (address deployed);
    function feeBps() external view returns (uint16);
    function getApproved(uint256 id) external view returns (address result);
    function getNonceIsSet(address user, uint256 nonce) external view returns (bool);
    function getTokenData(uint256 id) external view returns (bool minted, uint8 nonce);
    function invalidateNonce(uint256 nonce) external;
    function isApprovedForAll(address owner, address operator) external view returns (bool result);
    function mint(address to, uint256 id, uint8 nonce) external;
    function mintAndBuyWithSig(
        address to,
        uint256 id,
        uint8 saltNonce,
        address beneficiary,
        uint256 sellerPrice,
        address buyer,
        uint256 nonce,
        uint256 deadline,
        bytes memory signature
    ) external payable;
    function name() external pure returns (string memory);
    function owner() external view returns (address result);
    function ownerOf(uint256 id) external view returns (address result);
    function ownershipHandoverExpiresAt(address pendingOwner) external view returns (uint256 result);
    function permitForAll(address owner, address operator, uint256 nonce, uint256 deadline, bytes memory signature)
        external;
    function renderer() external view returns (address);

    function royaltyInfo(uint256 tokenId, uint256 salePrice)
        external
        view
        returns (address receiver, uint256 royaltyAmount);
    function safeTransferFrom(address from, address to, uint256 id) external payable;
    function safeTransferFrom(address from, address to, uint256 id, bytes memory data) external payable;
    function setApprovalForAll(address operator, bool isApproved) external;
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
    function symbol() external pure returns (string memory);
    function tokenURI(uint256 id) external view returns (string memory);
    function transferFrom(address from, address to, uint256 id) external payable;
    function withdraw(address to, uint256 amount) external;
}

function deployIntoEnvironmentUsingCheatcodes() {
    address nonceIncreaser = 0x00000000000001E4A82b33373DE1334E7d8F4879;

    if (nonceIncreaser.code.length == 0) {
        __vmEtch(
            nonceIncreaser,
            hex"3d353d1a8060101161031357806080161561019f578060801161019f573d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df0505b806040161561026b573d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df0505b80602016156102d7573d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df0505b8060101615610313573d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df03df03df03df0505b7f03420372039f03c903f0041404350453046e0486049b04ad04bc04c804d104d790600f1660041b1c61ffff16565b3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3d3df03df03df03df03df03df03df0005b3d3d3d3d3d3d3d3df03df03df03df03df03df0005b3d3d3d3d3d3d3df03df03df03df03df0005b3d3d3d3d3d3df03df03df03df0005b3d3d3d3d3df03df03df0005b3d3d3d3df03df0005b3d3d3df0005b00"
        );
    }

    if (address(SUB_ZERO).code.length == 0) {
        __vmEtch(address(SUB_ZERO), SUB_ZERO_INITCODE);
        (bool success, bytes memory runtimeCode) = address(SUB_ZERO).call("");
        if (!success) {
            assembly ("memory-safe") {
                let freeMemoryPointer := mload(0x40)
                returndatacopy(freeMemoryPointer, 0, returndatasize())
                revert(freeMemoryPointer, returndatasize())
            }
        }
        __vmEtch(address(SUB_ZERO), runtimeCode);
    }
}

function __vmEtch(address to, bytes memory code) {
    address foundryVm = address(uint160(uint256(keccak256("hevm cheat code"))));
    (bool success,) = foundryVm.call(abi.encodeWithSignature("etch(address,bytes)", to, code));
    if (!success) {
        assembly ("memory-safe") {
            let freeMemoryPointer := mload(0x40)
            returndatacopy(freeMemoryPointer, 0, returndatasize())
            revert(freeMemoryPointer, returndatasize())
        }
    }
}
