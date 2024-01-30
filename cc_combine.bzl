load("@bazel_tools//tools/cpp:toolchain_utils.bzl", "find_cpp_toolchain")
load("@bazel_tools//tools/build_defs/cc:action_names.bzl", "CPP_LINK_STATIC_LIBRARY_ACTION_NAME")

def _get_obj_list(ctx):
    objects = []
    for dep_target in ctx.attr.deps:
        cc_info_linker_inputs = dep_target[CcInfo].linking_context.linker_inputs
        for linker_in in cc_info_linker_inputs.to_list():
            for linker_in_lib in linker_in.libraries:
                if linker_in_lib.pic_objects:
                    objects += linker_in_lib.pic_objects
                elif linker_in_lib.objects:
                    objects += linker_in_lib.objects
    return objects

def _cc_archive_impl(ctx):
    toolchain_for_cc = find_cpp_toolchain(ctx)
    object_list = _get_obj_list(ctx)
    output_file = ctx.actions.declare_file(ctx.label.name if ctx.label.name.startswith('lib') and ctx.label.name.endswith('.a') else 'lib' + ctx.label.name + ".a")

    configuration_feature = cc_common.configure_features(
        ctx = ctx,
        requested_features = ctx.features,
        unsupported_features = ctx.disabled_features,
        cc_toolchain = toolchain_for_cc,
    )

    linker_input = cc_common.create_linker_input(
        owner = ctx.label,
        libraries = depset(direct = [
            cc_common.create_library_to_link(
                actions = ctx.actions,
                cc_toolchain = toolchain_for_cc,
                feature_configuration = configuration_feature,
                pic_objects = object_list,
                static_library = output_file,
                pic_static_library = output_file,
            ),
        ]),
    )
    compilation_context = cc_common.create_compilation_context()
    linking_context = cc_common.create_linking_context(linker_inputs = depset(direct = [linker_input]))
    archiver_variables = cc_common.create_link_variables(
        feature_configuration = configuration_feature,
        cc_toolchain = toolchain_for_cc,
        output_file = output_file.path,
        is_using_linker = False,
    )
    archiver_path = cc_common.get_tool_for_action(
        feature_configuration = configuration_feature,
        action_name = CPP_LINK_STATIC_LIBRARY_ACTION_NAME,
    )
    command_line = cc_common.get_memory_inefficient_command_line(
        feature_configuration = configuration_feature,
        action_name = CPP_LINK_STATIC_LIBRARY_ACTION_NAME,
        variables = archiver_variables,
    )
    args = ctx.actions.args()
    args.add_all(command_line)
    for obj in object_list:
        args.add(obj)

    env = cc_common.get_environment_variables(
        feature_configuration = configuration_feature,
        action_name = CPP_LINK_STATIC_LIBRARY_ACTION_NAME,
        variables = archiver_variables,
    )

    ctx.actions.run(
        executable = archiver_path,
        arguments = [args],
        env = env,
        inputs = depset(
            direct = object_list,
            transitive = [
                toolchain_for_cc.all_files,
            ],
        ),
        outputs = [output_file],
    )

    cc_info = cc_common.merge_cc_infos(cc_infos = [
        CcInfo(compilation_context = compilation_context, linking_context = linking_context),
    ])
    return [DefaultInfo(files = depset([output_file])), cc_info]

def _cc_combine_impl(ctx):
    if ctx.attr.genshared == True:
        return [] # Not implent
    else:
        return _cc_archive_impl(ctx)

cc_combine = rule(
    implementation = _cc_combine_impl,
    fragments = ["cpp"],
    attrs = {
        "_cc_toolchain": attr.label(default = Label("@bazel_tools//tools/cpp:current_cc_toolchain")),
        "deps": attr.label_list(providers = [CcInfo]),
        "genshared" : attr.bool(default = False)
    },
    toolchains = ["@bazel_tools//tools/cpp:toolchain_type"],
)
