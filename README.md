5G-CN implementation
========================

This is a basic implementation of a 5G Core Network supporting 4G LTE control signalling. It is important to notice that we
are still developing functionality and making the specific changes to make it full 5G CN compliant.

This implementation is composed by:
1. Authenticator: This component is in charge of manage all the control messages that will arrive from the gNB
2. UPF: SDN controller containing the required rules to encap/decap GTP-U traffic

## Information
The authenticator can be split into different modules in order to correctly match with the architecture proposed by 5G.
Moreover, we have been working with lagopus as a Virtual Switch implementation. Other implementations have not been teste yet.

## Author
Ginés García Avilés [website](https://www.it.uc3m.es/gigarcia/index.html)

## Acknowledgments
* [5G MoNArch] (https://5g-monarch.eu/)
