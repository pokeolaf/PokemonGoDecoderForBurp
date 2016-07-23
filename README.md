# PokemonGoDecoderForBurp
A simpe decoder to decode requests/responses made by PokemonGo in burp


To Install:


    git clone https://github.com/pokeolaf/PokemonGoDecoderForBurp.git

    git submodule update --init --recursive

    cd src/main/proto

    python compile.py -l java

    cd ../../..

    mvn compile

    mvn package

This will create a file "PokemonBurpExtension-jar-with-dependencies.jar" in the target folder. 

In Burp: in the Extender tab: "add": choose "Java" as extension type and select the PokemonBurpExtension-jar-with-dependencies.jar Hit "Next", then "Close" (if any Output or Error message apear, something is broken. Please inform me about that)

Now you can decode some parts of the intercepted Pokemon Go traffic.
Some parts are not jet reverse engenered thus we dont know what those bytes mean :(
