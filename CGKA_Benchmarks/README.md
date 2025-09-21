# Amigo CGKA Benchmarks

This repository consists of the libraries, tests, and benchmarks used to implement and evaluate the Amigo CGKA.

- The **src/** folder contains three libraries:  
  - `upke.rs` — instantiates the UPKE primitive  
  - `tree.rs` — provides mechanisms for instantiating and modifying ratchet trees  
  - `member.rs` — leverages the prior libraries to intiate and apply group state and application operations 

## Docker environment
The container resulting from the included Dockerfile was tested with Rust image 1.84.1 and docker version 24.0.7 on a MacBook Pro M2 with 24G of RAM. 

## Running the Benchmarks

This repository contains a **Dockerfile** that includes the necessary files to create a docker image that can be used to run our CGKA benchmarks, displaying CGKA operation timings and message sizes.

To build the image, run the following in a terminal in the root directory of the repository:

`docker build -t rust-bench .`

Once built, run the container.

`docker run --rm rust-bench`


# Additional Notes
While our Docker image can be run on a local PC, the appropriate hardware needs to be employed to achieve numbers consistent with our paper. Our CGKA benchmarks were run on a Raspberry Pi and a Moto E smartphone.  These device specifications are found in Section 7. 

On a local PC or Raspberry Pi, this image can be used to obtain the data used to calculate all our CGKA benchmarks.  This includes the timing measurements displayed in Figure 5 as well as Table 7 and 8.

This Docker image will also generate the ciphertext sizes displayed in Figure 10. 

For energy benchmarks, our methodology is found in Appendix D.  Following this methodology, this image can be used to calculate the energy measurements displayed in Table 5, Table 6, and Table 9.

To run these benchmarks on an android phone, we utilized [Dinghy](https://github.com/sonos/dinghy), a cross-compilation library for running Rust benchmarks.  Our benchmarking code in **src/benches** was compiled for the Moto E architecture via Dinghy, and pushed to the phone's **/data/local/tmp/** directory via [adb](https://developer.android.com/tools/adb)).  Via an adb shell, we then executed the benchmark executable.

