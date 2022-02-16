from .pyconcrete import LWEParams

########################
# 128 bits of security #
########################

# 128 bits of security with a dimension of 256 (LWE estimator, September 15th 2020)
LWE128_256 = LWEParams(256, -5)

# 128 bits of security with a dimension of 512 (LWE estimator, September 15th 2020)
LWE128_512 = LWEParams(512, -11)

# 128 bits of security with a dimension of 630 (LWE estimator, September 15th 2020)
LWE128_630 = LWEParams(630, -14)

# 128 bits of security with a dimension of 650 (LWE estimator, September 15th 2020)
LWE128_650 = LWEParams(650, -15)

# 128 bits of security with a dimension of 688 (LWE estimator, September 15th 2020)
LWE128_688 = LWEParams(688, -16)

# 128 bits of security with a dimension of 710 (LWE estimator, September 15th 2020)
LWE128_710 = LWEParams(710, -17)

# 128 bits of security with a dimension of 750 (LWE estimator, September 15th 2020)
LWE128_750 = LWEParams(750, -18)

# 128 bits of security with a dimension of 800 (LWE estimator, September 15th 2020)
LWE128_800 = LWEParams(800, -19)

# 128 bits of security with a dimension of 830 (LWE estimator, September 15th 2020)
LWE128_830 = LWEParams(830, -20)

# 128 bits of security with a dimension of 1024 (LWE estimator, September 15th 2020)
LWE128_1024 = LWEParams(1024, -25)

# 128 bits of security with a dimension of 2048 (LWE estimator, September 15th 2020)
LWE128_2048 = LWEParams(2048, -52) # warning u32

# 128 bits of security with a dimension of 4096 (LWE estimator, September 15th 2020)
LWE128_4096 = LWEParams(4096, -105) # warning u64

########################
# 80 bits of security  #
########################

# 80 bits of security with a dimension of 256 (LWE estimator, September 15th 2020)
LWE80_256 = LWEParams(256, -9)

# 80 bits of security with a dimension of 512 (LWE estimator, September 15th 2020)
LWE80_512 = LWEParams(512, -19)

# 80 bits of security with a dimension of 630 (LWE estimator, September 15th 2020)
LWE80_630 = LWEParams(630, -24)

# 80 bits of security with a dimension of 650 (LWE estimator, September 15th 2020)
LWE80_650 = LWEParams(650, -25)

# 80 bits of security with a dimension of 688 (LWE estimator, September 15th 2020)
LWE80_688 = LWEParams(688, -26)

# 80 bits of security with a dimension of 710 (LWE estimator, September 15th 2020)
LWE80_710 = LWEParams(710, -27)

# 80 bits of security with a dimension of 750 (LWE estimator, September 15th 2020)
LWE80_750 = LWEParams(750, -29)

# 80 bits of security with a dimension of 800 (LWE estimator, September 15th 2020)
LWE80_800 = LWEParams(800, -31) #warning u32

# 80 bits of security with a dimension of 830 (LWE estimator, September 15th 2020)
LWE80_830 = LWEParams(830, -32) #warning u32

# 80 bits of security with a dimension of 1024 (LWE estimator, September 15th 2020)
LWE80_1024 = LWEParams(1024, -40) #warning u32

# 80 bits of security with a dimension of 2048 (LWE estimator, September 15th 2020)
LWE80_2048 = LWEParams(2048, -82) #warning u64
