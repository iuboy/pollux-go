package keycrypt

import (
	"crypto/elliptic"
	"math/big"
)

// MarshalECPointUncompressed 编码椭圆曲线点为未压缩格式 0x04||X||Y，
// 输出与已弃用的 elliptic.Marshal 逐字节一致。
//
// 仅供内部比较/指纹用途：SM2 等非标准曲线不能走 ecdsa.PublicKey.ECDH()
// （非 NIST 曲线 panic），故手工按曲线位长填充坐标。
func MarshalECPointUncompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) / 8
	buf := make([]byte, 1+2*byteLen)
	buf[0] = 4
	x.FillBytes(buf[1 : 1+byteLen])
	y.FillBytes(buf[1+byteLen:])
	return buf
}
