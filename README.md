# portscan

Небольшой Go-пакет, который проверяет, открыты ли TCP-порты на хостах (обычный TCP connect).
Только стандартная библиотека, без глобального состояния — удобно встраивать в свои программы.

Сканируйте только те узлы, которые вам разрешено проверять.

## Установка

Нужен Go 1.25.5+.

```bash
go get github.com/ilyaytrewq/postscan/portscan
```

## Пример

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/ilyaytrewq/postscan/portscan"
)

func main() {
	ports, err := portscan.ParsePorts("22,80,443,8000-8100")
	if err != nil {
		log.Fatal(err)
	}

	scanner, err := portscan.New(portscan.WithConnectTimeout(500 * time.Millisecond))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := scanner.Scan(ctx, []string{"127.0.0.1"}, ports)
	if err != nil {
		log.Fatal(err)
	}
	for r := range results {
		fmt.Printf("%s:%d %s\n", r.Host, r.Port, r.State)
	}
}
```

## Как это работает

- `New(opts...)` создаёт сканер. Он неизменяемый и его можно использовать из нескольких горутин.
- `Scan` возвращает канал с результатами по мере готовности, в произвольном порядке.
  Дочитайте канал до конца или отмените контекст — иначе скан может зависнуть.
- `ScanAll` делает то же самое, но собирает всё в слайс. Для больших сканов лучше `Scan`.
- Контекст ограничивает весь скан, включая DNS. `WithConnectTimeout` — только одну попытку подключения.
- Ошибки во входных данных (нет целей, битая цель, пустой набор портов) возвращаются сразу из `Scan`.
  Всё, что связано с сетью, приходит в `Result.State`.

**Цели** — IPv4/IPv6-адреса, DNS-имена или CIDR (до 65 536 адресов). Если имя резолвится в несколько
адресов, проверяется каждый (или только первый с `WithFirstAddrOnly()`).

**Порты** задаются через `ParsePorts("22,80,8000-9000")`, `List(22, 80)`, `Range(1, 1024)` или `Union(...)`.

## Опции

| Опция | По умолчанию | Что делает |
|---|---|---|
| `WithConcurrency(n)` | `100` | максимум одновременных подключений (1–4096) |
| `WithConnectTimeout(d)` | `2s` | таймаут одной попытки подключения |
| `WithFirstAddrOnly()` | выкл. | брать только первый адрес из DNS |
| `WithDialer(d)` | `net.Dialer` | свой способ подключения (например, для тестов) |
| `WithResolver(r)` | `net.DefaultResolver` | свой DNS-резолвер |

## Состояния

| `State` | Значение |
|---|---|
| `StateOpen` | соединение установлено |
| `StateClosed` | соединение отклонено |
| `StateTimeout` | нет ответа за отведённое время |
| `StateUnreachable` | хост или сеть недоступны |
| `StateCanceled` | скан отменён через контекст |
| `StateUnresolved` | имя не разрешилось |
| `StateError` | другая ошибка |

## Тесты

```bash
go test -race ./...
```

## Лицензия

MIT

<details>
<summary>Полный текст</summary>

```text
MIT License

Copyright (c) 2026 Ilya Tikhonov

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

</details>
