diagrams:
	docker run --rm --entrypoint sh -v $(PWD)/docs/design/diagrams:/data plantuml/plantuml@sha256:47870c1f76cfb3747bc7090bfe83013a4e3105b5a0bb1515e2baf5d3e2b3ee9d -c 'find /data -name "*.puml" ! -name "_*" ! -path "*/rendered/*" ! -path "*/_*/*" | while read f; do d=`dirname "$${f#/data/}"`; mkdir -p "/data/rendered/$$d"; java -jar /opt/plantuml.jar -tsvg -o "/data/rendered/$$d" "$$f"; done'

clean:
	rm -rf docs/design/diagrams/rendered

# Compila la tesi in due PDF distinti dalla stessa sorgente: thesis_Verrengia.pdf (versione
# completa, con dedica e ringraziamenti) e thesis_Verrengia_no-ringraziamenti.pdf (identica,
# con la dedica ma senza i ringraziamenti — per condividere con il relatore).
# no-ringraziamenti.flag pilota l'\ifNoRingraziamenti dichiarato in thesis_Verrengia.tex; -g
# forza latexmk a ricompilare anche se il sorgente .tex non è cambiato (l'unica cosa diversa tra
# le due build è la presenza del flag file). Ogni variante ha la propria sottocartella sotto
# ThesisAtUniud/build/, cosi i due insiemi di file generati (aux/log/pdf/...) non si mescolano;
# il sorgente .tex resta fuori da build/ — spostare anche quello romperebbe ogni
# \input/\includegraphics relativo.
thesis:
	cd ThesisAtUniud && rm -f no-ringraziamenti.flag && latexmk -pdf -synctex=1 -interaction=nonstopmode -g -outdir=build/with-dedica -jobname=thesis_Verrengia thesis_Verrengia.tex

thesis-no-ringraziamenti:
	cd ThesisAtUniud && touch no-ringraziamenti.flag && latexmk -pdf -synctex=1 -interaction=nonstopmode -g -outdir=build/no-ringraziamenti -jobname=thesis_Verrengia_no-ringraziamenti thesis_Verrengia.tex && rm -f no-ringraziamenti.flag

thesis-both: thesis thesis-no-ringraziamenti

.PHONY: diagrams clean thesis thesis-no-ringraziamenti thesis-both
