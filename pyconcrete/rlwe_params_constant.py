from .pyconcrete import RLWEParams

######################################
# 128 bits of security - dimension 1 #
######################################

# 128 bits of security with a polynomial_size of 1 and a dimension of 256 (LWE estimator, September 15th 2020)
RLWE128_256_1 = RLWEParams(1, 256, -5)
# 128 bits of security with a polynomial_size of 1 and a dimension of 512 (LWE estimator, September 15th 2020)
RLWE128_512_1 = RLWEParams(1, 512, -11)
# 128 bits of security with a polynomial_size of 1 and a dimension of 1024 (LWE estimator, September 15th 2020)
RLWE128_1024_1 = RLWEParams(1, 1024, -25)
# 128 bits of security with a polynomial_size of 1 and a dimension of 2048 (LWE estimator, September 15th 2020)
RLWE128_2048_1 = RLWEParams(1, 2048, -52) # warning u32
# 128 bits of security with a polynomial_size of 1 and a dimension of 4096 (LWE estimator, September 15th 2020)
RLWE128_4096_1 = RLWEParams(1, 4096, -105) # warning u64

######################################
# 128 bits of security - dimension 2 #
######################################

# 128 bits of security with a polynomial_size of 2 and a dimension of 256 (LWE estimator, September 15th 2020)
RLWE128_256_2 = RLWEParams(2, 256, -11)
# 128 bits of security with a polynomial_size of 2 and a dimension of 512 (LWE estimator, September 15th 2020)
RLWE128_512_2 = RLWEParams(2, 512, -25)

######################################
# 128 bits of security - dimension 4 #
######################################

# 128 bits of security with a polynomial_size of 4 and a dimension of 256 (LWE estimator, September 15th 2020)
RLWE128_256_4 = RLWEParams(4, 256, -25)

#####################################
# 80 bits of security - dimension 1 #
#####################################

# 80 bits of security with a polynomial_size of 1 and a dimension of 256 (LWE estimator, September 15th 2020)
RLWE80_256_1 = RLWEParams(1, 256, -9)
# 80 bits of security with a polynomial_size of 1 and a dimension of 512 (LWE estimator, September 15th 2020)
RLWE80_512_1 = RLWEParams(1, 512, -19)
# 80 bits of security with a polynomial_size of 1 and a dimension of 1024 (LWE estimator, September 15th 2020)
RLWE80_1024_1 = RLWEParams(1, 1024, -40) # warning u32
# 80 bits of security with a polynomial_size of 1 and a dimension of 2048 (LWE estimator, September 15th 2020)
RLWE80_2048_1 = RLWEParams(1, 2048, -82) # warning u64

#####################################
# 80 bits of security - dimension 2 #
#####################################

# 80 bits of security with a polynomial_size of 2 and a dimension of 256 (LWE estimator, September 15th 2020)
RLWE80_256_2 = RLWEParams(2, 256, -19)
# 80 bits of security with a polynomial_size of 2 and a dimension of 512 (LWE estimator, September 15th 2020)
RLWE80_512_2 = RLWEParams(2, 512, -40) # warning u32

#####################################
# 80 bits of security - dimension 4 #
#####################################

# 80 bits of security with a polynomial_size of 4 and a dimension of 256 (LWE estimator, September 15th 2020)
RLWE80_256_4 = RLWEParams(4, 256, -40) # warning u32
