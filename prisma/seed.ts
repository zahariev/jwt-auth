import { PrismaClient } from '@prisma/client';
const prisma = new PrismaClient();

async function main() {
    const prismaModels = {
        user: [
            {
                email: 'zaharievboyan@gmail.com',
            },
            {
                email: 'asda@hotmail.com',
            },
        ],
        donation: [
            {
                email: 'zaharievboyan@gmail.com',
                displayName: 'Boyan Zahariev',
                count: 5,
            },
        ],
    };

    const dbTables = {
        user: 'users',
        donation: 'donations',
    };

    seed(dbTables, prismaModels);
}

main()
    .then(async () => {
        await prisma.$disconnect();
    })
    .catch(async (e) => {
        console.error(e);
        await prisma.$disconnect();
    });

function seed(dbTables, prismaModels) {
    Object.keys(dbTables).forEach((model, i) => {
        console.log(dbTables[model]);
        Promise.all([
            prisma[model].deleteMany().then(() => {
                console.log('deleted Many');
                prisma
                    .$executeRawUnsafe(`ALTER SEQUENCE ${dbTables[model]}_id_seq RESTART WITH 1`)
                    .then(() => {
                        console.log('alter sequence');
                        setTimeout(() => {
                            prismaModels[model]?.map((data) => {
                                Promise.all([
                                    prisma[model]
                                        .create({
                                            data,
                                        })
                                        .then(() => {
                                            console.log('create');

                                            console.log(model);

                                            console.log(data);
                                        }),
                                ]);
                            });
                        }, 100 * i);
                    });
            }),
        ]);
    });
}