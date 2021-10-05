# 7111 cut 1
Sti7111

Retirar cwpk

Isso é baseado em pdf de exploração segura. http://www.security-explorations.com/

Obrigado por este trabalho incrível!, mas eu continuo na minha esse amigo do security-explorations, é um Payserver

Ok, vamos ...

O primeiro a box precisa ter a porta uart ativa (TX / RX).

Às vezes, os (nabos) dos engenheiros cometem erros,  (para sorte dos Payservers)

Após entrar na Box deve-se verificar se este é vulnerável ou não.

Digita o cmd.

peek fe00d05c

Se este der um valor em hex  0x01100110 (continue), caso aparece o valor 0x00000000 não continue, desculpa, isso não é para ti.

A chave final está no endereço fe24c020. 

Digite por favor

display fe24c020 4

Sortudo, podes jogar no euromilhões que vais acertar na nucha

 Ps: em breve colocarei aqui o code para Visual Studio net c#
