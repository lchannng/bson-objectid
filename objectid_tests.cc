/*
 * File  : objectid.cc
 * Author: lchannng <l.channng@gmail.com>
 * Date  : 2021/07/10 12:11:11
 */

#include "objectid.hpp"
#include <iostream>

int main(int, char**)
{
    auto oid1 = ijk::objectid::generate();

    auto soid = oid1.to_string();
    std::cout << "oid1: " << soid << " gen_time: " << oid1.gen_time() << std::endl; 
    auto oid2 = ijk::objectid::from_string(soid);
    std::cout << "oid2: " << oid2.to_string() << std::endl; 
    std::cout << "ois1 == oid2: " << (oid1 == oid2) << std::endl;

    auto oid3 = ijk::objectid::from_string("60e94bbbdc83993c10d6e7d0");
    std::cout << "oid3: " << " gen_time: " << oid3.gen_time() << std::endl; 

    auto oid4 = ijk::objectid::generate();
    std::cout << "ois1 != oid4: " << (oid1 != oid4) << std::endl;

    return 0; 
}
