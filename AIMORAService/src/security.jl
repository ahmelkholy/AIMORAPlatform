# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
struct PathPolicy
    allowed_roots::Vector{String}
    max_path_bytes::Int
end

function PathPolicy(roots::AbstractVector{<:AbstractString}, max_path_bytes::Integer)
    max_path_bytes >= 256 ||
        throw(ServiceError("INVALID_REQUEST", "The path limit is too small."))
    canonical_roots = String[]
    for root in roots
        ncodeunits(root) <= max_path_bytes ||
            throw(ServiceError("PATH_NOT_ALLOWED", "An allowed root exceeds the path limit."))
        isdir(root) ||
            throw(ServiceError("PATH_NOT_ALLOWED", "An allowed root does not exist."))
        push!(canonical_roots, realpath(root))
    end
    unique!(canonical_roots)
    isempty(canonical_roots) &&
        throw(ServiceError("PATH_NOT_ALLOWED", "At least one allowed root is required."))
    return PathPolicy(canonical_roots, Int(max_path_bytes))
end

function constant_time_equal(left::AbstractString, right::AbstractString)
    left_bytes = codeunits(left)
    right_bytes = codeunits(right)
    maximum_length = max(length(left_bytes), length(right_bytes))
    difference = xor(length(left_bytes), length(right_bytes))
    for index in 1:maximum_length
        left_byte = index <= length(left_bytes) ? left_bytes[index] : 0x00
        right_byte = index <= length(right_bytes) ? right_bytes[index] : 0x00
        difference |= xor(Int(left_byte), Int(right_byte))
    end
    return difference == 0
end

function _path_is_inside(candidate::AbstractString, root::AbstractString)
    current = dirname(String(candidate))
    canonical_root = String(root)

    while true
        try
            samefile(current, canonical_root) && return true
        catch
            return false
        end

        parent = dirname(current)
        parent == current && return false
        current = parent
    end
end

function confine_existing_file(policy::PathPolicy, requested_path::AbstractString)
    ncodeunits(requested_path) <= policy.max_path_bytes ||
        throw(ServiceError("PATH_NOT_ALLOWED", "The requested path exceeds the limit."))
    isfile(requested_path) ||
        throw(ServiceError("RESOURCE_NOT_FOUND", "The requested file does not exist."))
    canonical_path = realpath(requested_path)
    any(root -> _path_is_inside(canonical_path, root), policy.allowed_roots) ||
        throw(ServiceError("PATH_NOT_ALLOWED", "The requested file is outside allowed roots."))
    return canonical_path
end

function bounded_file_size(path::AbstractString, maximum_bytes::Integer)
    size = Int(stat(path).size)
    size <= maximum_bytes ||
        throw(ServiceError("RESOURCE_TOO_LARGE", "The requested file exceeds the limit."))
    return size
end

function sha256_file(path::AbstractString)
    return open(path, "r") do io
        bytes2hex(SHA.sha256(io))
    end
end

function read_file_window(
    path::AbstractString,
    offset::Integer,
    length::Integer,
    maximum_window_bytes::Integer,
)
    offset >= 0 || throw(ServiceError("INVALID_REQUEST", "Window offset must be nonnegative."))
    length >= 0 || throw(ServiceError("INVALID_REQUEST", "Window length must be nonnegative."))
    length <= maximum_window_bytes ||
        throw(ServiceError("RESOURCE_TOO_LARGE", "The requested window exceeds the limit."))
    file_size = Int(stat(path).size)
    offset <= file_size ||
        throw(ServiceError("INVALID_REQUEST", "Window offset exceeds the artifact size."))
    effective_length = min(Int(length), file_size - Int(offset))
    return open(path, "r") do io
        seek(io, Int(offset))
        read(io, effective_length)
    end
end
