package self_test

// peer_params_race_test.go 锁定第四轮审计 #2:SendDatagram / AddPath 在 app
// goroutine 上读取 peer transport parameters 必须持 peerParamsMutex——0-RTT
// 场景下 DialEarly 返回后,app goroutine 与连接 goroutine 的
// handleTransportParameters 写入(服务器 EncryptedExtensions 到达)并发,
// 未加锁的读取被 -race 捕获(上游 quic-go#4303 的同类缺口)。
//
// 用例名挂 Test0RTT 前缀,使其进入 `go test -race -run 'Test0RTT' ./...` 的
// 专项回归命令。

import (
	"context"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/stretchr/testify/require"
)

func Test0RTTPeerParamsRaceWithDatagramAndPath(t *testing.T) {
	serverConn := newUDPConnLocalhost(t)
	tr := &quic.Transport{Conn: serverConn}
	defer tr.Close()
	ln, err := tr.ListenEarly(
		getTLSConfig(),
		getQuicConfig(&quic.Config{Allow0RTT: true, EnableDatagrams: true}),
	)
	require.NoError(t, err)
	defer ln.Close()

	clientConn := newUDPConnLocalhost(t)
	clientTLSConf := dialAndReceiveTicket(t, ln, clientConn, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	dialConn := newUDPConnLocalhost(t)
	conn, err := quic.DialEarly(ctx, dialConn, serverConn.LocalAddr(), clientTLSConf, getQuicConfig(&quic.Config{EnableDatagrams: true, Allow0RTT: true}))
	require.NoError(t, err)
	defer conn.CloseWithError(0, "")

	// 服务器端的 EncryptedExtensions(真正的 transport parameters 写入点)
	// 在此 goroutine 处理握手期间到达;app goroutine 同时并发读。
	stop := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		// 另一个 Transport 供 AddPath 发起新路径(迁移语义要求独立 PacketConn)。
		pathConn := newUDPConnLocalhost(t)
		defer pathConn.Close()
		pathTr := &quic.Transport{Conn: pathConn}
		defer pathTr.Close()

		// 发送上限压在 datagramQueue 容量(maxDatagramSendQueueLen = 32)以内,
		// 避免读循环在 queue 满时阻塞在 Add 上。
		const sendCap = 31
		sentOK := 0
		deadline := time.Now().Add(200 * time.Millisecond)
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// 参数到达前返回 disabled 错误(nil peerParams 不 panic),
			// 到达后成功入队——两条路径都触发对 peerParams 的加锁读。
			if sentOK < sendCap {
				if err := conn.SendDatagram([]byte("peer params race")); err == nil {
					sentOK++
				}
			}
			if i%8 == 0 {
				_, _ = conn.AddPath(pathTr)
			}
			if i%64 == 0 && time.Now().After(deadline) {
				return
			}
		}
	}()

	serverConnHandle, err := ln.Accept(ctx)
	require.NoError(t, err)
	defer serverConnHandle.CloseWithError(0, "")

	// 握手完成 = handleTransportParameters 写入已发生(与上面的读并发)。
	require.Eventually(t, func() bool {
		return conn.ConnectionState().TLS.HandshakeComplete
	}, 2*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond) // 让读循环覆盖写入后的窗口
	close(stop)
	<-readerDone

	// 行为回归:参数到达后 SendDatagram 可正常入队(参数未到时返回 disabled
	// 错误)。端到端收发由 TestDatagramNegotiation 覆盖;DATAGRAM 帧本身不重
	// 传,这里不对投递成功率做断言。
	require.NoError(t, conn.SendDatagram([]byte("post-handshake datagram")))
}
