require systemtap_${PV}.bb

inherit_defer native

addtask addto_recipe_sysroot after do_populate_sysroot before do_build
