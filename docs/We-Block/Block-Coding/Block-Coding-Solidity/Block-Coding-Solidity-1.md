# Block Coding | 初识Solidity #1

程序，每个人每天都在接触，每天叫醒你起床的闹钟就是一个很简单的程序，每天你用来与朋友聊天的通讯软件也是一个程序，而你手机上，电脑上安装的各色程序，就是你通往这个互联网的门户。

其实在web3中也有这样类似的程序，无论是代币也好还是大众最熟悉的NFT或者说数字藏品，其实本质上都是基于一个一个智能合约（Smart Contract）的。

![etherscan.PNG](.\etherscan.PNG)

![JaychouBAYC.png](.\JaychouBAYC.png)

### 所以什么是智能合约呢？

智能合约就像是一份自动执行的合同，只不过它们是基于区块链技术编写的。智能合约允许在没有第三方的情况下，直接在参与者之间进行交易和协商。

简单来说，智能合约就是一种把我们生活中的合约数字化，当满足一定条件后，可以由程序自动执行的技术。我们的生活中处处充满着合约，就好比你跟我做了一个约定，我们订好了奖惩措施，但由于种种原因可能没法履行其中的条款，出现了无法履约的情况，而在进入赔付环节，往往会出现毁约，失约，耍赖的情况，最后弄得有理说不清。但是如果我们把约定通过代码的形式，录入区块链中，一旦触发约定时的条件，就会有程序来自动执行，这就是智能合约。

我们可以用一个简单的例子来解释什么是智能合约：假设你想要在一个网站上购买一件商品。在传统的交易中，你需要向卖方支付钱款，卖方会将商品寄给你，如果商品有问题，你需要联系卖方退货或者维修。但是在使用智能合约的情况下，这个过程可以变得更加自动化和高效。

通过智能合约，你可以将钱款存放在一个安全的区块链账户中。当卖方确认收到了付款，智能合约就会自动释放资金，然后将商品的所有权转移到你的名下。如果商品没有问题，智能合约就会自动完成交易。如果商品有问题，智能合约也可以自动退款。

你可以把合约类比成互联网中的”后端“这个概念，不过实际上部分类比可以，但智能合约的功能比后端更加复杂和丰富。

就像互联网中的后端一样，智能合约也是应用程序的一部分，它运行在区块链的节点上，为应用程序提供数据处理和存储的功能。智能合约可以在区块链上执行代码，使得应用程序能够完成各种自动化任务和交易。智能合约也可以作为应用程序的接口，与前端进行交互。

但是，智能合约比后端更加安全可靠，因为智能合约的代码运行在区块链上，一旦被写入区块链，就无法被篡改。而且，智能合约的执行是由网络上的多个节点完成的，没有单点故障，保证了应用程序的稳定性和可靠性。

此外，智能合约还具有许多独特的特点，例如自动化、不可篡改、去中心化等，这些特点使得它们在应用场景上与传统的后端有很大的不同。因此，虽然可以部分将智能合约类比为互联网中的后端，但是智能合约是一种全新的技术，具有自身独特的功能和应用场景。

### Dapps？

DApps（去中心化应用）是建立在区块链技术上的应用程序。与传统的互联网应用程序不同，DApps不依赖于单一的中心化服务器，而是运行在分布式网络上，由多个节点组成的去中心化网络维护和管理。

类比于现实中的互联网应用程序，DApps就像是一个完全开放、自主管理的社区。就像在社区中，人们可以共同决定和执行事务，而不是被单一的中心管理机构所控制。同样，DApps的用户和参与者可以直接参与到应用程序的运作中，贡献资源和力量来维护网络的稳定性和安全性。

另外，与传统互联网应用程序相比，DApps通常具有以下特点：

1. 去中心化：DApps不依赖于中央服务器，而是由多个节点共同维护和管理。

2. 公开透明：DApps的所有操作都可以在区块链上被记录和查看，保证了数据的透明和公正。

3. 自主治理：DApps的用户和参与者可以直接参与到应用程序的决策和管理中，共同维护和发展网络。

总之，DApps是一种基于去中心化、公开透明、安全可靠、自主治理的新型应用程序，与传统互联网应用程序相比，具有更大的自由度和更广阔的发展前景。

一个例子是以太坊上的一个DApp，叫做Uniswap。Uniswap是一个去中心化的交易所，允许用户在以太坊上进行代币交换。与传统的中心化交易所不同，Uniswap不需要中心化的监管机构或中介机构，用户可以直接在应用程序中进行交易。

在Uniswap中，用户可以添加代币对，并根据市场供求的情况来确定交易价格。交易会在智能合约中进行，确保交易的安全和公正。此外，Uniswap的用户和参与者可以直接参与到应用程序的治理和决策中，共同决定应用程序的未来发展。

Uniswap作为一个DApp，具有去中心化、公开透明、安全可靠、自主治理等特点。它是以太坊生态系统中的重要组成部分，为用户提供了更加开放和自由的交易体验，也为区块链技术的应用拓展了更广阔的空间。

![Uniswap.PNG](.\Uniswap.PNG)

### About Coding

智能合约的编写语言通常取决于所使用的区块链平台。不同的区块链平台支持的编程语言不同，因此智能合约的编写语言也不尽相同。以下是几个主要区块链平台及其支持的智能合约编程语言：

1. 以太坊：Solidity、Vyper、Serpent、LLL、Bamboo

2. EOS：C++

3. TRON：Solidity、Java

4. NEO：C#, VB.Net、F#

5. Corda：Kotlin、Java

当然我们只会专注于Solidity语言，因为直到现在它仍然是最常被使用的合约编写语言之一。

> Solidity is a statically-typed curly-braces programming language designed for developing smart contracts that run on Ethereum.

#### Cryptozombie

那么我们就从Ethereum上一个经典的教学小游戏作为引子开始我们的探索吧...

第一节将创造一个"僵尸工厂"， 用它建立一支僵尸部队。

- 我们的工厂会把我们部队中所有的僵尸保存到数据库中
- 工厂会有一个函数能产生新的僵尸
- 每个僵尸会有一个随机的独一无二的面孔

在后面的课程里，我们会增加功能。比如，让僵尸能攻击人类或其它僵尸! 但是在实现这些好玩的功能之前，我们先要实现创建僵尸这样的基本功能。

#### 僵尸DNA如何运作

僵尸的面孔取决于它的DNA。它的DNA很简单，由一个16位的整数组成：

```
8356281049284737
```

如同真正的DNA, 这个数字的不同部分会对应不同的特点。 前2位代表头型，紧接着的2位代表眼睛，等等。

> 注: 本教程我们尽量简化。我们的僵尸只有7种头型(虽然2位数字允许100种可能性)。以后我们会加入更多的头型, 如果我们想让僵尸有更多造型。

例如，前两位数字是 `83`， 计算僵尸的头型，我们做`83 % 7 + 1` = 7 运算， 此僵尸将被赋予第七类头型。

在右边页面，移动头基因`head gene` 滑块到第七位置(圣诞帽)可见`83`所对应的特点。

![DNA.png](.\DNA.png)

#### 合约

从最基本的开始入手:

Solidity 的代码都包裹在**合约**里面. 一份`合约`就是以太应用的基本模块， 所有的变量和函数都属于一份合约, 它是你所有应用的起点.

一份名为 `HelloWorld` 的空合约如下:

```
contract HelloWorld {

}
```

#### 版本编译指示

所有的 Solidity 源码都必须冠以 "version pragma" — 标明 Solidity 编译器的版本. 以避免将来新的编译器可能破坏你的代码。

例如: `pragma solidity ^0.4.19;` （目前最新版本 ## **v0.8.17**）

这段代码我们将他称为版本编译指示

一般来说，源文件可以（而且应该）用版本 pragma 指令来注释， 以拒绝用未来的编译器版本进行编译，因为这可能会引入不兼容的变化。 我们力图把这类变更做到尽可能小， 我们需要以一种当修改语义时必须同步修改语法的方式引入变更， 当然这有时候也难以做到。正因为如此， 至少在包含重大变化的版本中，通读一下更新日志总是一个好主意。 这些版本总是有 `0.x.0` 或 `x.0.0` 形式的版本。

在前面的例子中，带有上述代码的源文件在 0.4.19 版本之前的编译器上不能编译， 在 0.5.0 版本之后的编译器上也不能工作（这第二个条件是通过使用 `^` 添加的）。 因为在 `0.6.0` 版本之前不会有任何重大的变化， 所以您可以确信您的代码是按照您的预期编译的。 上面例子中不固定编译器的具体版本号，因此编译器的补丁版也可以使用。

综上所述， 下面就是一个最基本的合约 — 每次建立一个新的项目时的第一段代码:

```
pragma solidity ^0.4.19;

contract HelloWorld {

}
```

#### 实战演习

为了建立我们的僵尸部队， 让我们先建立一个基础合约，称为 `ZombieFactory`。

1. 在右边的输入框里输入 `0.4.19`，我们的合约基于这个版本的编译器。

2. 建立一个空合约 `ZombieFactory`。

![code_block1.png](.\code_block1.png)

That's it, 你就拥有了自己的第一个合约了！


