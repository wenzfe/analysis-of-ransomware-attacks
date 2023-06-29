@echo off

echo "running black ..."
black %1% 
echo "running isort ..."
isort %1%
echo "running pylint ..."
pylint %1%