# Configurazione condivisa da chiunque compili questa tesi con latexmk — sia il Makefile in
# radice (target 'thesis'/'thesis-no-dedica', che passano comunque -outdir esplicito e quindi
# hanno sempre la precedenza su questo file), sia un editor con auto-compile all'salvataggio
# (es. LaTeX Workshop su VS Code), che di norma usa latexmk come motore e legge questo file da
# solo, senza bisogno di configurazione aggiuntiva nell'editor stesso.
#
# Objettivo: nessuno strumento deve più scrivere file generati (aux/log/pdf/...) nella cartella
# sorgente di ThesisAtUniud/ — vanno tutti in build/with-dedica/, la stessa cartella che produce
# 'make thesis'. Se l'editor sta ancora scrivendo nella root nonostante questo file, vuol dire
# che chiama pdflatex/bibtex direttamente invece di latexmk, o sovrascrive $out_dir con una sua
# impostazione esplicita — in quel caso serve intervenire nella configurazione dell'editor stesso.
$out_dir = 'build/with-dedica';
$pdf_mode = 1;
$synctex = 1;
