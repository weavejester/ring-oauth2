FROM clojure:alpine

ENV CODE /code/
RUN mkdir $CODE
WORKDIR $CODE

ADD ./ $CODE
CMD ["lein", "repl"]
