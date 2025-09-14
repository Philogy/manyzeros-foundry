// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {ISaltSalesList} from "src/ISaltSalesList.sol";
import {deployIntoEnvironmentUsingCheatcodes, SUB_ZERO} from "src/ISubZero.sol";

/// @author philogy <https://github.com/philogy>
contract SaltSalesListTest is Test {
    ISaltSalesList public saltSalesList;
    address constant saltOwner = 0x2c8B14A270eb080c2662A12936BB6B2BaBF15BF8;
    address saltList = makeAddr("saltList");
    address salesOwner = makeAddr("salesOwner");

    function setUp() external {
        vm.etch(
            saltList,
            hex"001793d6018032514d0204ea96fe0db812e9c6fcbdf8019c242a1b1b48875f6d2412350276cfd38b0cae59807e1f4e9300f9dbd2e112ae986247cf6254036849a0741ace776e1f16714101f3085785122473a19fb2245f027c36406406230481ec5784f101839695e10433579db44e88ef011db611dd1508ea2c55ce762b01c464679904e58ed67f11a89900a2a86fe1030fdd518ee9c55300ca6b41481de67b3538e36db6032e76f8a018e65762b32ca3a703403837b4"
        );
        deployIntoEnvironmentUsingCheatcodes();
        saltSalesList = ISaltSalesList(
            deployCode(
                "src/SaltSalesList.vy",
                abi.encode(
                    saltOwner,
                    saltList,
                    ISaltSalesList.StartState({
                        owner: salesOwner,
                        next10: 0,
                        next12: 5,
                        next14: 13,
                        price10: 0.005e4,
                        price12: 0.008e4,
                        price14: 0.8e4
                    })
                )
            )
        );
        vm.prank(saltOwner);
        SUB_ZERO.setApprovalForAll(address(saltSalesList), true);
        vm.deal(salesOwner, 1 wei);
    }

    function test_simpleBuy() public {
        address buyer = makeAddr("buyer");
        hoax(buyer, 0.005 ether);
        uint256 salt = saltSalesList.buy_salt{value: 0.005 ether}(10);
        assertEq(SUB_ZERO.ownerOf(salt), buyer);
    }
}
