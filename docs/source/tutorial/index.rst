*****************************
Getting Started With botocore
*****************************


The ``botocore`` package provides a low-level interface to Amazon
services.  It is responsible for:

* Providing access to all available services
* Providing access to all operations within a service
* Marshaling all parameters for a particular operation in the correct format
* Signing the request with the correct authentication signature
* Receiving the response and returning the data in native Python data structures

``botocore`` does not provide higher-level abstractions on top of these
services, operations and responses.  That is left to the application
layer.  The goal of ``botocore`` is to handle all of the low-level details
of making requests and getting results from a service.

The ``botocore`` package is mainly data-driven.  Each service has a JSON
description which specifies all of the operations the service supports,
all of the parameters the operation accepts, all of the documentation
related to the service, information about supported regions and endpoints, etc.
Because this data can be updated quickly based on the canonical description
of these services, it's much easier to keep ``botocore`` current.

Using Botocore
==============

The first step in using botocore is to create a ``Session`` object.
``Session`` objects then allow you to create individual clients::

    import botocore.session
    session = botocore.session.get_session()
    client = session.create_client('ec2', region_name='us-west-2')

Once you have that client created, each operation provided by the service is
mapped to a method.  Each method takes ``**kwargs`` that maps to the parameter
names exposed by the service.  For example, using the ``client`` object created
above::

    for reservation in client.describe_instances()['Reservations']:
        for instance in reservation['Instances']:
            print(instance['InstanceId'])

    # All instances that are in a state of pending.
    reservations = client.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["pending"]}])

Sourcing Credentials From an External Process
==============================================

A profile can obtain credentials by running an external command through the
``credential_process`` setting.  Because a misbehaving command could otherwise
hang forever or emit unbounded output and stall every AWS worker thread,
botocore runs the command with two limits that apply to the initial load and
to every later refresh:

* ``credential_process_timeout`` - the maximum number of seconds the command
  is allowed to run.  The default is 60 seconds.
* ``credential_process_max_output_size`` - the maximum number of bytes the
  command may write to stdout.  The default is 65536 bytes (64 KB).

If the command exceeds either limit, exits with a non-zero status, or returns
invalid JSON, botocore terminates the process and raises a
``CredentialRetrievalError``.  The command's stdout and stderr are not
included in the error because they can contain secrets; the message only
describes the failure mode (for example ``credential process timed out after
60 seconds``).

The command is always executed as an argument list without a shell.  A slow
but legitimate provider can be accommodated by raising the limits in the
shared config file::

    [profile my-profile]
    credential_process = /opt/bin/my-credential-provider
    credential_process_timeout = 120
    credential_process_max_output_size = 131072

The same settings can be supplied with the ``AWS_CREDENTIAL_PROCESS_TIMEOUT``
and ``AWS_CREDENTIAL_PROCESS_MAX_OUTPUT_SIZE`` environment variables.  Both
values must be positive integers; a value of zero or a negative number raises
an ``InvalidConfigError``.
