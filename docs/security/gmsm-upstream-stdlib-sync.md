# emmansun/gmsm smx509 与 crypto/x509 的两处同步缺口(上游 issue 草稿)

> **状态:草稿,未提交。** 提交到 github.com/emmansun/gmsm/issues 属对外动作,由维护者决定后执行;本文档按"可直接粘贴"标准撰写。
>
> 来源:pollux-go 第三轮全量安全审查 M6。两处缺口均在 gmsm **v0.45.0**(截至 2026-10-18 的最新版本)上实证复现,复现环境为 go1.27.2 darwin/arm64。

---

## 缺口 1(主要):excluded IP 名称约束可被绕过(host bits 未归一化)

### 上游对应

| 项 | 值 |
| --- | --- |
| Go issue | [golang/go#79833](https://github.com/golang/go/issues/79833) "crypto/x509: excluded IP networks not properly applied" |
| 修复 CL | [CL 787220](https://go.dev/cl/787220) "crypto/x509: normalize IP name constraints with non-zero host bits"(commit `4093d5e62bfbeff315ccd76b63a5e58b7b128675`,约 2026-06,Go 1.27 携带) |
| gmsm 现状 | v0.45.0 `smx509/constraints.go` 的 `newIPNetConstraints` 无归一化逻辑 |

### 根因(三层)

1. **解析层保留 host bits**:`smx509/parser.go` 将约束按 DER 原样存入 `&net.IPNet{IP: net.IP(ip), Mask: net.IPMask(mask)}`——地址 `10.200.200.200/255.0.0.0` 的 IP 不做掩码。这一点与 stdlib 相同(stdlib 的修复刻意让"parsed constraint 保持编码原样")。
2. **约束集合不归一化**:stdlib 修复在 `newIPNetConstraints` 里为排序/查找建立掩码副本(`constraints.go:164-180`,注释:"Subtrees may carry non-zero host bits. Sort and search need the masked network address");gmsm 缺失整个掩码块。
3. **比较器不一致**:集合排序用 `ipNetworkCompare`(原始 `bytes.Compare(a.IP, b.IP)`),二分查找用 `ipBinarySearch`(同样是原始 IP 比较),而命中判定 `ipMatch` 用 `net.IPNet.Contains`(按掩码比较)。host bits 非零时,条目的"排序位置"与"匹配语义"错位。

`search()` 未命中时只回看**一个**邻居(`set[i-1]`)。因此:

- **单条约束不触发**(易漏测):插入点为 0 时回退到 `set[0]`,恰好能匹配。
- **两条约束触发**:让一条干净的小网络约束(如 `9.9.9.9/32`)占据目标 IP 的邻居槽位,host-bits 约束(`10.200.200.200/8`)按原始 IP 排在目标之后,二分只检查邻居槽位 → 真正应当排除的 `10.0.0.0/8` 从未被检查。

### 实际影响

一个(攻击者控制的)中间 CA,其证书携带"host bits 非零的 excluded IP 约束 + 一条不相干的干净 IP 约束",可让对该网段内地址的排除**静默失效**。同一链 crypto/x509(Go 1.27)拒绝、smx509 放行。所有经由 smx509 校验的证书链(GM/国密路径的 SM2 证书,以及 smx509 兼容处理的传统证书)均受影响。

### 复现

要点:两个库的 `CreateCertificate` 序列化 NameConstraints 时都会掩码 IP(`x509.go` 的 `ipAndMask`),所以必须用 `ExtraExtensions` 手工编码扩展,把 host bits 原样写进 DER。

```go
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	std "crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"net"
	"time"

	gm "github.com/emmansun/gmsm/smx509"
	"golang.org/x/crypto/cryptobyte"
	casn1 "golang.org/x/crypto/cryptobyte/asn1"
)

func nameConstraintsExt(addrs ...[]byte) (pkix.Extension, error) {
	var subtrees cryptobyte.Builder
	for _, a := range addrs {
		subtrees.AddASN1(casn1.SEQUENCE, func(seq *cryptobyte.Builder) {
			seq.AddASN1(casn1.Tag(7).ContextSpecific(), func(ip *cryptobyte.Builder) {
				ip.AddBytes(a) // address||mask 原样,不掩码
			})
		})
	}
	subtreeBytes, err := subtrees.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}
	var b cryptobyte.Builder
	b.AddASN1(casn1.SEQUENCE, func(nc *cryptobyte.Builder) {
		nc.AddASN1(casn1.Tag(1).ContextSpecific().Constructed(), func(ex *cryptobyte.Builder) {
			ex.AddBytes(subtreeBytes)
		})
	})
	val, err := b.Bytes()
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{
		Id:       asn1.ObjectIdentifier{2, 5, 29, 30}, // id-ce-nameConstraints
		Critical: true,
		Value:    val,
	}, nil
}

func main() {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()

	ext, _ := nameConstraintsExt(
		[]byte{10, 200, 200, 200, 255, 0, 0, 0}, // 网络 10.0.0.0/8,地址带 host bits
		[]byte{9, 9, 9, 9, 255, 255, 255, 255},   // 9.9.9.9/32:占据二分邻居槽位
	)
	caTmpl := &std.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: std.KeyUsageCertSign | std.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
		ExtraExtensions: []pkix.Extension{ext},
	}
	caDER, _ := std.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caStd, _ := std.ParseCertificate(caDER)
	caGm, _ := gm.ParseCertificate(caDER)

	leafTmpl := &std.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "leaf"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: std.KeyUsageDigitalSignature,
		IPAddresses: []net.IP{net.IP{10, 1, 2, 3}}, // 落在 10.0.0.0/8 内,应被排除
	}
	leafDER, _ := std.CreateCertificate(rand.Reader, leafTmpl, caStd, &leafKey.PublicKey, caKey)
	leafStd, _ := std.ParseCertificate(leafDER)
	leafGm, _ := gm.ParseCertificate(leafDER)

	poolStd := std.NewCertPool(); poolStd.AddCert(caStd)
	poolGm := gm.NewCertPool(); poolGm.AddCert(caGm)
	_, errStd := leafStd.Verify(std.VerifyOptions{Roots: poolStd})
	_, errGm := leafGm.Verify(gm.VerifyOptions{Roots: poolGm})
	fmt.Printf("crypto/x509: %v\n", errStd)
	fmt.Printf("smx509:      %v\n", errGm)
}
```

go1.27.2 + gmsm v0.45.0 实际输出:

```text
crypto/x509: x509: a root or intermediate certificate is not authorized to sign for this name: IP address "10.1.2.3" is excluded by constraint "10.0.0.0/8"
smx509:      <nil>   # ← 绕过:排除约束未生效
```

补充观察:仅保留单条 host-bits 约束时 smx509 也能拦截(回退 `set[0]` 的巧合),但错误信息为未归一化的 `10.200.200.200/8`(stdlib 显示 `10.0.0.0/8`)——单条用例会漏掉该缺陷,建议测试用例至少包含两条。

### 建议补丁

同步 stdlib `crypto/x509/constraints.go:164-180` 的掩码块到 `smx509/constraints.go` 的 `newIPNetConstraints`:

```go
	for _, n := range l {
		// Subtrees may carry non-zero host bits. Sort and search need the masked
		// network address, so use a copy and leave the parsed constraint as encoded.
		if masked := n.IP.Mask(n.Mask); masked != nil && !masked.Equal(n.IP) {
			n = &net.IPNet{IP: masked, Mask: n.Mask}
		}
		if len(n.IP) == net.IPv4len {
			ipv4 = append(ipv4, n)
		} else {
			ipv6 = append(ipv6, n)
		}
	}
```

---

## 缺口 2(次要):parseRFC2821Mailbox 缺少 stdlib 后续硬化

### 现状对照

stdlib(Go 1.27)`crypto/x509/verify.go` `parseRFC2821Mailbox` 尾部:

```go
	in = in[1:]

	// The RFC species a format for domains, but that's known to be
	// violated in practice so we accept that anything after an '@' is the
	// domain part.
	if !domainNameValid(in, false) {
		return mailbox, false
	}

	// Reject domain names containing @.
	if strings.ContainsRune(in, '@') {
		return mailbox, false
	}
```

gmsm v0.45.0 `smx509/verify.go`(parseRFC2821Mailbox 尾部)仍是旧快照:

```go
	in = in[1:]

	// The RFC species a format for domains, but that's known to be
	// violated in practice so we accept that anything after an '@' is the
	// domain part.
	if _, ok := domainToReverseLabels(in); !ok {
		return mailbox, false
	}
```

gmsm 的 `domainToReverseLabels` 对标签字符只检查 `c < 33 || c > 126`,即**接受域内 `@`** 等任意可打印字符;stdlib 的 `domainNameValid`(LDH 规则)+ 显式 `@` 拒绝则不接受。

### 实证(CA 携带 `ExcludedEmailAddresses: ["user@evil.example"]`,叶子 email SAN 各异)

| 叶子 email SAN | crypto/x509 (go1.27) | gmsm smx509 v0.45.0 |
| --- | --- | --- |
| `user@example.com` | 通过 | 通过 |
| `user@a@evil.example` | **拒绝**(畸形 SAN,验证失败) | **通过** |
| `user@example..com` | 拒绝 | 拒绝 |
| `user@exa mple.com` | 拒绝 | 拒绝 |

即:stdlib 判定为畸形、不可用的证书(域内 `@`),经 smx509 校验可用。这是跨库行为分歧而非直接绕过——但任何依赖"stdlib 会拒"的上层策略在 GM 路径上会失效。

### 建议补丁

同步 stdlib 上述尾部两段检查(需一并同步 `domainNameValid`,若尚不存在)。

---

## 对 pollux-go 的影响与建议

- pollux-go 的 GM 路径证书校验(`tlcp`/`https` 经 smx509)继承上述行为。缺口 1 意味着:**在依赖 IP 名称约束做网络隔离的场景里,GM 校验路径不应作为唯一防线**,直至 gmsm 修复并升级。
- 两个缺口均为 gmsm 侧修复(照抄 stdlib 对应实现即可),pollux-go 不做本地 fork 补丁(vendored 依赖中仅 quic-go 一处 fork;为 gmsm 引入 fork 的维护成本高于等待上游)。
- 建议 gmsm 项目建立 crypto/x509 基线 diff 的定期检查(本轮审查还发现 smx509 曾整体遗漏 Go 1.27 的 ML-DSA 相关枚举,已由 pollux-go 侧独立修复,参见仓库 CHANGELOG),降低后续同步缺口概率。

## 附:提 issue 时建议的标题

- `[smx509] excluded IP name constraints with non-zero host bits can be silently skipped (missing golang/go#79833 fix)`
- `[smx509] parseRFC2821Mailbox lacks domainNameValid / '@'-in-domain hardening from stdlib`
