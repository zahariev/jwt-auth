import { OrderByParams } from './../graphql';
import { PrismaService } from 'src/prisma/prisma.service';
import { Injectable } from '@nestjs/common';
import { UpdateDonationInput } from './dto/update-donation.input';
import { Prisma } from '@prisma/client';

@Injectable()
export class DonationsService {
    constructor(private prisma: PrismaService) {}
    create(createDonationInput: Prisma.DonationCreateInput) {
        return this.prisma.donation.create({
            data: createDonationInput,
        });
    }

    findAll(orderBy?: OrderByParams) {
        const { field, direction } = orderBy || {};
        return this.prisma.donation.findMany({
            orderBy: { [field]: direction },
        });
    }

    findOne(id: number) {
        return this.prisma.donation.findUnique({
            where: { id },
        });
    }

    update(id: number, updateDonationInput: UpdateDonationInput) {
        return `This action updates a #${id} donation`;
    }

    remove(id: number) {
        return `This action removes a #${id} donation`;
    }
}