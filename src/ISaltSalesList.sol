// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @author philogy <https://github.com/philogy>
interface ISaltSalesList {
    error Unauthorized();
    error WrongValue();
    error UnsupportedZeros();
    error MaxSearchIterations();
    error SaltsSoldOut();
    error MissingDesiredZeros();
    error PriceAboveMax();

    struct StartState {
        address owner;
        uint16 next10;
        uint16 next12;
        uint16 next14;
        uint16 price10;
        uint16 price12;
        uint16 price14;
    }

    function buy_salt(uint8 zeros) external payable returns (uint256);
    function get_owner() external view returns (address);
    function get_prices() external view returns (uint256, uint256, uint256);
    function update_index(uint8 zeros, uint256 iterations) external;
}
