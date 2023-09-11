cd /home/regress/CantianKernel/build
sh Makefile.sh all
cp -rf /home/regress/CantianKernel/output/bin  /home/regress/CantianKernel/pkg/
cp -rf /home/regress/CantianKernel/output/lib  /home/regress/CantianKernel/pkg/
echo ${CTDB_HOME}
if [[ ! -d ${CTDB_HOME}/data ]]; then
    mkdir -p ${CTDB_HOME}/data
fi