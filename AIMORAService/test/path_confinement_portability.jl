# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
using AIMORAService
using Test

@testset "AIMORAService path confinement portability" begin
    mktempdir() do root
        policy = PathPolicy([root], 4096)

        nested_root = joinpath(root, "nested")
        mkpath(nested_root)
        nested = joinpath(nested_root, "inside.aimora")
        write(nested, "nested canonical project fixture")
        @test confine_existing_file(policy, nested) == realpath(nested)

        dotted_inside = joinpath(root, "..allowed.aimora")
        write(dotted_inside, "dotted canonical project fixture")
        @test confine_existing_file(policy, dotted_inside) == realpath(dotted_inside)

        sibling_root = root * "-sibling"
        mkpath(sibling_root)
        try
            sibling = joinpath(sibling_root, "outside.aimora")
            write(sibling, "outside")
            error = try
                confine_existing_file(policy, sibling)
                nothing
            catch caught
                caught
            end
            @test error isa ServiceError
            @test error.code == "PATH_NOT_ALLOWED"
        finally
            rm(sibling_root; recursive = true, force = true)
        end
    end
end
