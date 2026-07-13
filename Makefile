diagrams:
	docker run --rm --entrypoint sh -v $(PWD)/docs/design/diagrams:/data plantuml/plantuml@sha256:47870c1f76cfb3747bc7090bfe83013a4e3105b5a0bb1515e2baf5d3e2b3ee9d -c 'find /data -name "*.puml" ! -name "_*" ! -path "*/rendered/*" ! -path "*/_*/*" | while read f; do d=`dirname "$${f#/data/}"`; mkdir -p "/data/rendered/$$d"; java -jar /opt/plantuml.jar -tsvg -o "/data/rendered/$$d" "$$f"; done'

clean:
	rm -rf docs/design/diagrams/rendered

.PHONY: diagrams clean
